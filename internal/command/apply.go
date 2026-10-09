package command

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/pavlenkoa/vault-secrets-generator/internal/config"
	"github.com/pavlenkoa/vault-secrets-generator/internal/engine"
	"github.com/pavlenkoa/vault-secrets-generator/internal/fetcher"
	"github.com/pavlenkoa/vault-secrets-generator/internal/vault"
)

var (
	applyDryRun  bool
	applyForce   bool
	applyTarget  []string
	applyExclude []string
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply secrets to Vault",
	Long: `Apply reads the configuration file and syncs secrets to Vault.

For each secret defined in the configuration:
- Remote files are fetched and values extracted via json/yaml/raw functions
- Generated passwords are created based on strategy (default: create only if missing)
- Vault references are copied from other Vault paths
- Commands are executed and output captured
- Static values are used as-is

Use --dry-run to see what changes would be made without applying them.
Use --target to apply specific secrets by label.
Use --exclude to skip specific secrets by label.`,
	Example: `  # Apply all secrets
  vsg apply --config config.hcl

  # Apply with variable override
  vsg apply --config config.hcl --var ENV=prod

  # Dry-run to see changes
  vsg apply --config config.hcl --dry-run

  # Force regeneration of generated secrets
  vsg apply --config config.hcl --force

  # Apply specific secrets by label
  vsg apply --config config.hcl --target prod-app
  vsg apply --config config.hcl -t prod-app -t prod-db

  # Apply all except specific secrets
  vsg apply --config config.hcl --exclude broken-secret
  vsg apply --config config.hcl -e broken -e legacy`,
	RunE: runApply,
}

func init() {
	rootCmd.AddCommand(applyCmd)

	applyCmd.Flags().BoolVar(&applyDryRun, "dry-run", false, "show what would be done without making changes")
	applyCmd.Flags().BoolVar(&applyForce, "force", false, "force regeneration of generated secrets")
	applyCmd.Flags().StringSliceVarP(&applyTarget, "target", "t", nil, "target specific secrets by label (comma-separated or repeated)")
	applyCmd.Flags().StringSliceVarP(&applyExclude, "exclude", "e", nil, "exclude secrets by label (comma-separated or repeated)")
}

func runApply(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	log := getLogger()

	// Load config
	cfgPath, err := getConfigFile()
	if err != nil {
		return err
	}

	log.Debug("loading config", "path", cfgPath)

	vars := parseVars()
	cfg, err := config.Load(cfgPath, vars)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Create Vault client
	log.Debug("connecting to vault", "address", cfg.Vault.Address)

	vaultClient, err := vault.NewClient(cfg.Vault)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: failed to connect to Vault:", err)
		os.Exit(ExitVaultError)
	}

	// Check Vault health
	if err := vaultClient.CheckHealth(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Error: Vault health check failed:", err)
		os.Exit(ExitVaultError)
	}

	// Set up fetchers
	registry := setupFetchers(ctx)

	// Create engine
	eng := engine.NewEngine(vaultClient, registry, cfg.Defaults, log)

	// Run reconciliation
	opts := engine.Options{
		DryRun:  applyDryRun,
		Force:   applyForce,
		Target:  applyTarget,
		Exclude: applyExclude,
	}

	result, err := eng.Reconcile(ctx, cfg, opts)
	if err != nil {
		return err
	}

	// Print diff
	if result.Diff.HasChanges() || verbose {
		fmt.Println(engine.FormatDiff(result.Diff))
	} else {
		fmt.Println("No changes required.")
	}

	// Handle errors
	if len(result.Errors) > 0 {
		fmt.Fprintln(os.Stderr, "\nErrors:")
		for _, e := range result.Errors {
			fmt.Fprintln(os.Stderr, " -", e.Error())
		}
		os.Exit(ExitPartialFailure)
	}

	// Report result
	if applyDryRun {
		adds, updates, deletes, _, _ := result.Diff.Summary()
		changes := adds + updates + deletes
		if changes > 0 {
			fmt.Printf("\nDry-run complete. %d changes would be made.\n", changes)
		}
	} else if result.Applied {
		fmt.Println("\nSecrets applied successfully.")
	}

	return nil
}

// setupFetchers creates and configures the fetcher registry
func setupFetchers(ctx context.Context) *fetcher.Registry {
	registry := fetcher.NewRegistry()

	// Local file fetcher
	registry.Register(fetcher.NewLocalFetcher())

	// S3 fetcher (optional - only if we might need it)
	s3Fetcher, err := fetcher.NewS3Fetcher(ctx)
	if err != nil {
		// Log but don't fail - S3 might not be needed
		getLogger().Debug("S3 fetcher not available", "error", err)
	} else {
		registry.Register(s3Fetcher)
	}

	// AWS Secrets Manager fetcher (aws_sm function)
	smFetcher, err := fetcher.NewAWSSMFetcher(ctx)
	if err != nil {
		getLogger().Debug("AWS Secrets Manager fetcher not available", "error", err)
	} else {
		registry.Register(smFetcher)
	}

	return registry
}

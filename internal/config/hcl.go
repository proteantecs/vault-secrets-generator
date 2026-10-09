package config

import (
	"fmt"
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// Variables holds CLI --var values and environment variable overrides.
type Variables map[string]string

// ParseHCL parses HCL configuration data with the given variables.
func ParseHCL(data []byte, filename string, vars Variables) (*Config, error) {
	file, diags := hclsyntax.ParseConfig(data, filename, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing HCL: %s", diags.Error())
	}

	// Build evaluation context with custom functions
	evalCtx := buildEvalContext(vars)

	// Parse top-level blocks
	content, diags := file.Body.Content(rootSchema)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing config structure: %s", diags.Error())
	}

	cfg := &Config{
		Secrets: make(map[string]SecretBlock),
		Defaults: Defaults{
			Generate: PasswordPolicy{
				Digits:  -1, // sentinel: not set
				Symbols: -1, // sentinel: not set
			},
		},
	}

	// Process blocks
	for _, block := range content.Blocks {
		switch block.Type {
		case "vault":
			vault, err := parseVaultBlock(block, evalCtx)
			if err != nil {
				return nil, fmt.Errorf("parsing vault block: %w", err)
			}
			cfg.Vault = *vault

		case "defaults":
			defaults, err := parseDefaultsBlock(block, evalCtx)
			if err != nil {
				return nil, fmt.Errorf("parsing defaults block: %w", err)
			}
			cfg.Defaults = *defaults

		case "secret":
			if len(block.Labels) != 1 {
				return nil, fmt.Errorf("secret block requires exactly one label (name)")
			}
			name := block.Labels[0]

			// Check for duplicate names
			if _, exists := cfg.Secrets[name]; exists {
				return nil, fmt.Errorf("duplicate secret block name: %q", name)
			}

			secretBlock, err := parseSecretBlock(block, name, evalCtx)
			if err != nil {
				return nil, fmt.Errorf("parsing secret block %q: %w", name, err)
			}

			cfg.Secrets[name] = *secretBlock
		}
	}

	// Apply defaults
	applyDefaults(cfg)

	// Validate
	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// rootSchema defines the top-level HCL structure
var rootSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "vault"},
		{Type: "defaults"},
		{Type: "secret", LabelNames: []string{"name"}},
	},
}

// buildEvalContext creates the HCL evaluation context with custom functions
func buildEvalContext(vars Variables) *hcl.EvalContext {
	return &hcl.EvalContext{
		Functions: map[string]function.Function{
			"env":           makeEnvFunction(vars),
			"generate":      makeGenerateFunction(),
			"json":          makeSourceFunction("json"),
			"aws_sm":        makeAWSSMFunction(),
			"yaml":          makeSourceFunction("yaml"),
			"raw":           makeRawFunction(),
			"vault":         makeVaultFunction(),
			"command":       makeCommandFunction(),
			"bcrypt":        makeBcryptFunction(),
			"argon2":        makeArgon2Function(),
			"pbkdf2":        makePbkdf2Function(),
			"sha1_htpasswd": makeSha1HtpasswdFunction(),
		},
	}
}

// makeEnvFunction creates the env() function for variable lookup
func makeEnvFunction(vars Variables) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "name", Type: cty.String},
		},
		Type: function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			name := args[0].AsString()
			// CLI vars take priority over env vars
			if val, ok := vars[name]; ok {
				return cty.StringVal(val), nil
			}
			if val := os.Getenv(name); val != "" {
				return cty.StringVal(val), nil
			}
			return cty.NullVal(cty.String), fmt.Errorf("variable %q is not set", name)
		},
	})
}

// valueMarkerType is the cty object type for value markers
var valueMarkerType = cty.Object(map[string]cty.Type{
	"_type":          cty.String,
	"_strategy":      cty.String,
	"_url":           cty.String,
	"_query":         cty.String,
	"_vault_path":    cty.String,
	"_vault_key":     cty.String,
	"_command":       cty.String,
	"_length":        cty.Number,
	"_digits":        cty.Number,
	"_symbols":       cty.Number,
	"_symbol_set":    cty.String,
	"_no_upper":      cty.Bool,
	"_allow_repeat":  cty.Bool,
	"_from":          cty.String,
	"_cost":          cty.Number,
	"_variant":       cty.String,
	"_memory":        cty.Number,
	"_iterations":    cty.Number,
	"_parallelism":   cty.Number,
	"_encoding":      cty.String,
	"_username":      cty.String,
	"_username_from": cty.String,
})

// makeGenerateFunction creates the generate() function
func makeGenerateFunction() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{},
		VarParam: &function.Parameter{
			Name: "options",
			Type: cty.DynamicPseudoType,
		},
		Type: function.StaticReturnType(valueMarkerType),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			result := map[string]cty.Value{
				"_type":          cty.StringVal("generate"),
				"_strategy":      cty.StringVal(""),
				"_url":           cty.StringVal(""),
				"_query":         cty.StringVal(""),
				"_vault_path":    cty.StringVal(""),
				"_vault_key":     cty.StringVal(""),
				"_command":       cty.StringVal(""),
				"_length":        cty.NumberIntVal(0),
				"_digits":        cty.NumberIntVal(-1), // -1 means use default
				"_symbols":       cty.NumberIntVal(-1),
				"_symbol_set":    cty.StringVal(""),
				"_no_upper":      cty.False,
				"_allow_repeat":  cty.True,
				"_from":          cty.StringVal(""),
				"_cost":          cty.NumberIntVal(0),
				"_variant":       cty.StringVal(""),
				"_memory":        cty.NumberIntVal(0),
				"_iterations":    cty.NumberIntVal(0),
				"_parallelism":   cty.NumberIntVal(0),
				"_encoding":      cty.StringVal(""),
				"_username":      cty.StringVal(""),
				"_username_from": cty.StringVal(""),
			}

			// Parse named arguments from varargs
			for _, arg := range args {
				if arg.Type().IsObjectType() {
					for k, v := range arg.AsValueMap() {
						switch k {
						case "length":
							result["_length"] = v
						case "digits":
							result["_digits"] = v
						case "symbols":
							result["_symbols"] = v
						case "symbol_set":
							result["_symbol_set"] = v
						case "no_upper":
							result["_no_upper"] = v
						case "allow_repeat":
							result["_allow_repeat"] = v
						case "strategy":
							result["_strategy"] = v
						}
					}
				}
			}

			return cty.ObjectVal(result), nil
		},
	})
}

// makeSourceFunction creates the json() or yaml() function
func makeSourceFunction(sourceType string) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "url", Type: cty.String},
			{Name: "query", Type: cty.String},
		},
		VarParam: &function.Parameter{
			Name: "options",
			Type: cty.DynamicPseudoType,
		},
		Type: function.StaticReturnType(valueMarkerType),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			url := args[0].AsString()
			query := args[1].AsString()
			strategy := ""

			// Parse optional strategy from varargs
			for i := 2; i < len(args); i++ {
				arg := args[i]
				if arg.Type().IsObjectType() {
					if s, ok := arg.AsValueMap()["strategy"]; ok {
						strategy = s.AsString()
					}
				}
			}

			return cty.ObjectVal(map[string]cty.Value{
				"_type":          cty.StringVal(sourceType),
				"_strategy":      cty.StringVal(strategy),
				"_url":           cty.StringVal(url),
				"_query":         cty.StringVal(query),
				"_vault_path":    cty.StringVal(""),
				"_vault_key":     cty.StringVal(""),
				"_command":       cty.StringVal(""),
				"_length":        cty.NumberIntVal(0),
				"_digits":        cty.NumberIntVal(-1),
				"_symbols":       cty.NumberIntVal(-1),
				"_symbol_set":    cty.StringVal(""),
				"_no_upper":      cty.False,
				"_allow_repeat":  cty.True,
				"_from":          cty.StringVal(""),
				"_cost":          cty.NumberIntVal(0),
				"_variant":       cty.StringVal(""),
				"_memory":        cty.NumberIntVal(0),
				"_iterations":    cty.NumberIntVal(0),
				"_parallelism":   cty.NumberIntVal(0),
				"_encoding":      cty.StringVal(""),
				"_username":      cty.StringVal(""),
				"_username_from": cty.StringVal(""),
			}), nil
		},
	})
}

// makeAWSSMFunction creates aws_sm(secret, key): a key of a JSON secret in AWS
// Secrets Manager, resolved like json("awssm://<secret>", ".<key>").
func makeAWSSMFunction() function.Function {
	jsonFn := makeSourceFunction("json")
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "secret", Type: cty.String},
			{Name: "key", Type: cty.String},
		},
		VarParam: &function.Parameter{
			Name: "options",
			Type: cty.DynamicPseudoType,
		},
		Type: function.StaticReturnType(valueMarkerType),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			jsonArgs := append([]cty.Value{
				cty.StringVal("awssm://" + args[0].AsString()),
				cty.StringVal("." + args[1].AsString()),
			}, args[2:]...)
			return jsonFn.Call(jsonArgs)
		},
	})
}

// makeRawFunction creates the raw() function
func makeRawFunction() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "url", Type: cty.String},
		},
		VarParam: &function.Parameter{
			Name: "options",
			Type: cty.DynamicPseudoType,
		},
		Type: function.StaticReturnType(valueMarkerType),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			url := args[0].AsString()
			strategy := ""

			// Parse optional strategy from varargs
			for i := 1; i < len(args); i++ {
				arg := args[i]
				if arg.Type().IsObjectType() {
					if s, ok := arg.AsValueMap()["strategy"]; ok {
						strategy = s.AsString()
					}
				}
			}

			return cty.ObjectVal(map[string]cty.Value{
				"_type":          cty.StringVal("raw"),
				"_strategy":      cty.StringVal(strategy),
				"_url":           cty.StringVal(url),
				"_query":         cty.StringVal(""),
				"_vault_path":    cty.StringVal(""),
				"_vault_key":     cty.StringVal(""),
				"_command":       cty.StringVal(""),
				"_length":        cty.NumberIntVal(0),
				"_digits":        cty.NumberIntVal(-1),
				"_symbols":       cty.NumberIntVal(-1),
				"_symbol_set":    cty.StringVal(""),
				"_no_upper":      cty.False,
				"_allow_repeat":  cty.True,
				"_from":          cty.StringVal(""),
				"_cost":          cty.NumberIntVal(0),
				"_variant":       cty.StringVal(""),
				"_memory":        cty.NumberIntVal(0),
				"_iterations":    cty.NumberIntVal(0),
				"_parallelism":   cty.NumberIntVal(0),
				"_encoding":      cty.StringVal(""),
				"_username":      cty.StringVal(""),
				"_username_from": cty.StringVal(""),
			}), nil
		},
	})
}

// makeVaultFunction creates the vault() function
func makeVaultFunction() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "path", Type: cty.String},
			{Name: "key", Type: cty.String},
		},
		VarParam: &function.Parameter{
			Name: "options",
			Type: cty.DynamicPseudoType,
		},
		Type: function.StaticReturnType(valueMarkerType),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			vaultPath := args[0].AsString()
			vaultKey := args[1].AsString()
			strategy := ""

			// Parse optional strategy from varargs
			for i := 2; i < len(args); i++ {
				arg := args[i]
				if arg.Type().IsObjectType() {
					if s, ok := arg.AsValueMap()["strategy"]; ok {
						strategy = s.AsString()
					}
				}
			}

			return cty.ObjectVal(map[string]cty.Value{
				"_type":          cty.StringVal("vault"),
				"_strategy":      cty.StringVal(strategy),
				"_url":           cty.StringVal(""),
				"_query":         cty.StringVal(""),
				"_vault_path":    cty.StringVal(vaultPath),
				"_vault_key":     cty.StringVal(vaultKey),
				"_command":       cty.StringVal(""),
				"_length":        cty.NumberIntVal(0),
				"_digits":        cty.NumberIntVal(-1),
				"_symbols":       cty.NumberIntVal(-1),
				"_symbol_set":    cty.StringVal(""),
				"_no_upper":      cty.False,
				"_allow_repeat":  cty.True,
				"_from":          cty.StringVal(""),
				"_cost":          cty.NumberIntVal(0),
				"_variant":       cty.StringVal(""),
				"_memory":        cty.NumberIntVal(0),
				"_iterations":    cty.NumberIntVal(0),
				"_parallelism":   cty.NumberIntVal(0),
				"_encoding":      cty.StringVal(""),
				"_username":      cty.StringVal(""),
				"_username_from": cty.StringVal(""),
			}), nil
		},
	})
}

// makeCommandFunction creates the command() function
func makeCommandFunction() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "cmd", Type: cty.String},
		},
		VarParam: &function.Parameter{
			Name: "options",
			Type: cty.DynamicPseudoType,
		},
		Type: function.StaticReturnType(valueMarkerType),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			cmd := args[0].AsString()
			strategy := ""

			// Parse optional strategy from varargs
			for i := 1; i < len(args); i++ {
				arg := args[i]
				if arg.Type().IsObjectType() {
					if s, ok := arg.AsValueMap()["strategy"]; ok {
						strategy = s.AsString()
					}
				}
			}

			return cty.ObjectVal(map[string]cty.Value{
				"_type":          cty.StringVal("command"),
				"_strategy":      cty.StringVal(strategy),
				"_url":           cty.StringVal(""),
				"_query":         cty.StringVal(""),
				"_vault_path":    cty.StringVal(""),
				"_vault_key":     cty.StringVal(""),
				"_command":       cty.StringVal(cmd),
				"_length":        cty.NumberIntVal(0),
				"_digits":        cty.NumberIntVal(-1),
				"_symbols":       cty.NumberIntVal(-1),
				"_symbol_set":    cty.StringVal(""),
				"_no_upper":      cty.False,
				"_allow_repeat":  cty.True,
				"_from":          cty.StringVal(""),
				"_cost":          cty.NumberIntVal(0),
				"_variant":       cty.StringVal(""),
				"_memory":        cty.NumberIntVal(0),
				"_iterations":    cty.NumberIntVal(0),
				"_parallelism":   cty.NumberIntVal(0),
				"_encoding":      cty.StringVal(""),
				"_username":      cty.StringVal(""),
				"_username_from": cty.StringVal(""),
			}), nil
		},
	})
}

// makeBcryptFunction creates the bcrypt() function for password hashing
func makeBcryptFunction() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{},
		VarParam: &function.Parameter{
			Name: "options",
			Type: cty.DynamicPseudoType,
		},
		Type: function.StaticReturnType(valueMarkerType),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			result := map[string]cty.Value{
				"_type":          cty.StringVal("bcrypt"),
				"_strategy":      cty.StringVal(""),
				"_url":           cty.StringVal(""),
				"_query":         cty.StringVal(""),
				"_vault_path":    cty.StringVal(""),
				"_vault_key":     cty.StringVal(""),
				"_command":       cty.StringVal(""),
				"_length":        cty.NumberIntVal(0),
				"_digits":        cty.NumberIntVal(-1),
				"_symbols":       cty.NumberIntVal(-1),
				"_symbol_set":    cty.StringVal(""),
				"_no_upper":      cty.False,
				"_allow_repeat":  cty.True,
				"_from":          cty.StringVal(""),
				"_cost":          cty.NumberIntVal(0),
				"_variant":       cty.StringVal(""),
				"_memory":        cty.NumberIntVal(0),
				"_iterations":    cty.NumberIntVal(0),
				"_parallelism":   cty.NumberIntVal(0),
				"_encoding":      cty.StringVal(""),
				"_username":      cty.StringVal(""),
				"_username_from": cty.StringVal(""),
			}

			// Parse options from varargs
			for _, arg := range args {
				if arg.Type().IsObjectType() {
					for k, v := range arg.AsValueMap() {
						switch k {
						case "from":
							result["_from"] = v
						case "cost":
							result["_cost"] = v
						case "strategy":
							result["_strategy"] = v
						}
					}
				}
			}

			// Validate required 'from' parameter
			if result["_from"].AsString() == "" {
				return cty.NilVal, fmt.Errorf("bcrypt() requires 'from' parameter")
			}

			return cty.ObjectVal(result), nil
		},
	})
}

// makeArgon2Function creates the argon2() function for password hashing
func makeArgon2Function() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{},
		VarParam: &function.Parameter{
			Name: "options",
			Type: cty.DynamicPseudoType,
		},
		Type: function.StaticReturnType(valueMarkerType),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			result := map[string]cty.Value{
				"_type":          cty.StringVal("argon2"),
				"_strategy":      cty.StringVal(""),
				"_url":           cty.StringVal(""),
				"_query":         cty.StringVal(""),
				"_vault_path":    cty.StringVal(""),
				"_vault_key":     cty.StringVal(""),
				"_command":       cty.StringVal(""),
				"_length":        cty.NumberIntVal(0),
				"_digits":        cty.NumberIntVal(-1),
				"_symbols":       cty.NumberIntVal(-1),
				"_symbol_set":    cty.StringVal(""),
				"_no_upper":      cty.False,
				"_allow_repeat":  cty.True,
				"_from":          cty.StringVal(""),
				"_cost":          cty.NumberIntVal(0),
				"_variant":       cty.StringVal(""),
				"_memory":        cty.NumberIntVal(0),
				"_iterations":    cty.NumberIntVal(0),
				"_parallelism":   cty.NumberIntVal(0),
				"_encoding":      cty.StringVal(""),
				"_username":      cty.StringVal(""),
				"_username_from": cty.StringVal(""),
			}

			// Parse options from varargs
			for _, arg := range args {
				if arg.Type().IsObjectType() {
					for k, v := range arg.AsValueMap() {
						switch k {
						case "from":
							result["_from"] = v
						case "variant":
							result["_variant"] = v
						case "memory":
							result["_memory"] = v
						case "iterations":
							result["_iterations"] = v
						case "parallelism":
							result["_parallelism"] = v
						case "strategy":
							result["_strategy"] = v
						}
					}
				}
			}

			// Validate required 'from' parameter
			if result["_from"].AsString() == "" {
				return cty.NilVal, fmt.Errorf("argon2() requires 'from' parameter")
			}

			return cty.ObjectVal(result), nil
		},
	})
}

// makePbkdf2Function creates the pbkdf2() function for password hashing
func makePbkdf2Function() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{},
		VarParam: &function.Parameter{
			Name: "options",
			Type: cty.DynamicPseudoType,
		},
		Type: function.StaticReturnType(valueMarkerType),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			result := map[string]cty.Value{
				"_type":          cty.StringVal("pbkdf2"),
				"_strategy":      cty.StringVal(""),
				"_url":           cty.StringVal(""),
				"_query":         cty.StringVal(""),
				"_vault_path":    cty.StringVal(""),
				"_vault_key":     cty.StringVal(""),
				"_command":       cty.StringVal(""),
				"_length":        cty.NumberIntVal(0),
				"_digits":        cty.NumberIntVal(-1),
				"_symbols":       cty.NumberIntVal(-1),
				"_symbol_set":    cty.StringVal(""),
				"_no_upper":      cty.False,
				"_allow_repeat":  cty.True,
				"_from":          cty.StringVal(""),
				"_cost":          cty.NumberIntVal(0),
				"_variant":       cty.StringVal(""),
				"_memory":        cty.NumberIntVal(0),
				"_iterations":    cty.NumberIntVal(0),
				"_parallelism":   cty.NumberIntVal(0),
				"_encoding":      cty.StringVal(""),
				"_username":      cty.StringVal(""),
				"_username_from": cty.StringVal(""),
			}

			// Parse options from varargs
			for _, arg := range args {
				if arg.Type().IsObjectType() {
					for k, v := range arg.AsValueMap() {
						switch k {
						case "from":
							result["_from"] = v
						case "variant":
							result["_variant"] = v
						case "iterations":
							result["_iterations"] = v
						case "encoding":
							result["_encoding"] = v
						case "strategy":
							result["_strategy"] = v
						}
					}
				}
			}

			// Validate required 'from' parameter
			if result["_from"].AsString() == "" {
				return cty.NilVal, fmt.Errorf("pbkdf2() requires 'from' parameter")
			}

			return cty.ObjectVal(result), nil
		},
	})
}

// makeSha1HtpasswdFunction creates the sha1_htpasswd() function for htpasswd {SHA} format
func makeSha1HtpasswdFunction() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{},
		VarParam: &function.Parameter{
			Name: "options",
			Type: cty.DynamicPseudoType,
		},
		Type: function.StaticReturnType(valueMarkerType),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			result := map[string]cty.Value{
				"_type":          cty.StringVal("sha1_htpasswd"),
				"_strategy":      cty.StringVal(""),
				"_url":           cty.StringVal(""),
				"_query":         cty.StringVal(""),
				"_vault_path":    cty.StringVal(""),
				"_vault_key":     cty.StringVal(""),
				"_command":       cty.StringVal(""),
				"_length":        cty.NumberIntVal(0),
				"_digits":        cty.NumberIntVal(-1),
				"_symbols":       cty.NumberIntVal(-1),
				"_symbol_set":    cty.StringVal(""),
				"_no_upper":      cty.False,
				"_allow_repeat":  cty.True,
				"_from":          cty.StringVal(""),
				"_cost":          cty.NumberIntVal(0),
				"_variant":       cty.StringVal(""),
				"_memory":        cty.NumberIntVal(0),
				"_iterations":    cty.NumberIntVal(0),
				"_parallelism":   cty.NumberIntVal(0),
				"_encoding":      cty.StringVal(""),
				"_username":      cty.StringVal(""),
				"_username_from": cty.StringVal(""),
			}

			// Parse options from varargs
			for _, arg := range args {
				if arg.Type().IsObjectType() {
					for k, v := range arg.AsValueMap() {
						switch k {
						case "from":
							result["_from"] = v
						case "username":
							result["_username"] = v
						case "username_from":
							result["_username_from"] = v
						case "strategy":
							result["_strategy"] = v
						}
					}
				}
			}

			// Validate required 'from' parameter
			if result["_from"].AsString() == "" {
				return cty.NilVal, fmt.Errorf("sha1_htpasswd() requires 'from' parameter")
			}

			// Validate username: exactly one of username or username_from must be set
			hasUsername := result["_username"].AsString() != ""
			hasUsernameFrom := result["_username_from"].AsString() != ""
			if hasUsername && hasUsernameFrom {
				return cty.NilVal, fmt.Errorf("sha1_htpasswd() cannot have both 'username' and 'username_from'")
			}
			if !hasUsername && !hasUsernameFrom {
				return cty.NilVal, fmt.Errorf("sha1_htpasswd() requires either 'username' or 'username_from' parameter")
			}

			return cty.ObjectVal(result), nil
		},
	})
}

// parseVaultBlock parses the vault configuration block
func parseVaultBlock(block *hcl.Block, evalCtx *hcl.EvalContext) (*VaultConfig, error) {
	vault := &VaultConfig{}

	content, diags := block.Body.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{Name: "address"},
			{Name: "namespace"},
		},
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "auth"},
		},
	})
	if diags.HasErrors() {
		return nil, fmt.Errorf("%s", diags.Error())
	}

	// Parse attributes
	if attr, exists := content.Attributes["address"]; exists {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			return nil, fmt.Errorf("evaluating address: %s", diags.Error())
		}
		vault.Address = val.AsString()
	}

	if attr, exists := content.Attributes["namespace"]; exists {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			return nil, fmt.Errorf("evaluating namespace: %s", diags.Error())
		}
		vault.Namespace = val.AsString()
	}

	// Parse auth block
	for _, authBlock := range content.Blocks {
		if authBlock.Type == "auth" {
			auth, err := parseAuthBlock(authBlock, evalCtx)
			if err != nil {
				return nil, fmt.Errorf("parsing auth block: %w", err)
			}
			vault.Auth = *auth
		}
	}

	return vault, nil
}

// parseAuthBlock parses the auth configuration block
func parseAuthBlock(block *hcl.Block, evalCtx *hcl.EvalContext) (*AuthConfig, error) {
	auth := &AuthConfig{}

	content, diags := block.Body.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{Name: "method"},
			{Name: "token"},
			{Name: "role"},
			{Name: "role_id"},
			{Name: "secret_id"},
			{Name: "mount_path"},
		},
	})
	if diags.HasErrors() {
		return nil, fmt.Errorf("%s", diags.Error())
	}

	attrMap := map[string]*string{
		"method":     &auth.Method,
		"token":      &auth.Token,
		"role":       &auth.Role,
		"role_id":    &auth.RoleID,
		"secret_id":  &auth.SecretID,
		"mount_path": &auth.MountPath,
	}

	for name, ptr := range attrMap {
		if attr, exists := content.Attributes[name]; exists {
			val, diags := attr.Expr.Value(evalCtx)
			if diags.HasErrors() {
				return nil, fmt.Errorf("evaluating %s: %s", name, diags.Error())
			}
			*ptr = val.AsString()
		}
	}

	return auth, nil
}

// parseDefaultsBlock parses the defaults configuration block
func parseDefaultsBlock(block *hcl.Block, evalCtx *hcl.EvalContext) (*Defaults, error) {
	defaults := &Defaults{
		Strategy: DefaultStrategyDefaults(),
		Generate: DefaultPasswordPolicy(),
	}

	content, diags := block.Body.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{Name: "mount"},
			{Name: "version"},
		},
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "strategy"},
			{Type: "generate"},
		},
	})
	if diags.HasErrors() {
		return nil, fmt.Errorf("%s", diags.Error())
	}

	// Parse mount attribute (optional, defaults to "secret")
	if attr, exists := content.Attributes["mount"]; exists {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			return nil, fmt.Errorf("evaluating mount: %s", diags.Error())
		}
		defaults.Mount = val.AsString()
	}

	// Parse version attribute (optional, defaults to 0/auto-detect)
	if attr, exists := content.Attributes["version"]; exists {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			return nil, fmt.Errorf("evaluating version: %s", diags.Error())
		}
		n, _ := val.AsBigFloat().Int64()
		defaults.Version = int(n)
	}

	for _, innerBlock := range content.Blocks {
		switch innerBlock.Type {
		case "strategy":
			strategy, err := parseStrategyBlock(innerBlock, evalCtx)
			if err != nil {
				return nil, fmt.Errorf("parsing strategy block: %w", err)
			}
			defaults.Strategy = *strategy

		case "generate":
			policy, err := parseGenerateBlock(innerBlock, evalCtx)
			if err != nil {
				return nil, fmt.Errorf("parsing generate block: %w", err)
			}
			defaults.Generate = *policy
		}
	}

	return defaults, nil
}

// parseStrategyBlock parses the strategy defaults block
func parseStrategyBlock(block *hcl.Block, evalCtx *hcl.EvalContext) (*StrategyDefaults, error) {
	strategy := DefaultStrategyDefaults()

	content, diags := block.Body.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{Name: "generate"},
			{Name: "json"},
			{Name: "yaml"},
			{Name: "raw"},
			{Name: "static"},
			{Name: "command"},
			{Name: "vault"},
		},
	})
	if diags.HasErrors() {
		return nil, fmt.Errorf("%s", diags.Error())
	}

	attrMap := map[string]*Strategy{
		"generate": &strategy.Generate,
		"json":     &strategy.JSON,
		"yaml":     &strategy.YAML,
		"raw":      &strategy.Raw,
		"static":   &strategy.Static,
		"command":  &strategy.Command,
		"vault":    &strategy.Vault,
	}

	for name, ptr := range attrMap {
		if attr, exists := content.Attributes[name]; exists {
			val, diags := attr.Expr.Value(evalCtx)
			if diags.HasErrors() {
				return nil, fmt.Errorf("evaluating %s: %s", name, diags.Error())
			}
			*ptr = Strategy(val.AsString())
		}
	}

	return &strategy, nil
}

// parseGenerateBlock parses the generate defaults block
func parseGenerateBlock(block *hcl.Block, evalCtx *hcl.EvalContext) (*PasswordPolicy, error) {
	policy := PasswordPolicy{
		Digits:  -1, // sentinel: not set
		Symbols: -1, // sentinel: not set
	}

	content, diags := block.Body.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{Name: "length"},
			{Name: "digits"},
			{Name: "symbols"},
			{Name: "symbol_set"},
			{Name: "no_upper"},
			{Name: "allow_repeat"},
		},
	})
	if diags.HasErrors() {
		return nil, fmt.Errorf("%s", diags.Error())
	}

	if attr, exists := content.Attributes["length"]; exists {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			return nil, fmt.Errorf("evaluating length: %s", diags.Error())
		}
		n, _ := val.AsBigFloat().Int64()
		policy.Length = int(n)
	}

	if attr, exists := content.Attributes["digits"]; exists {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			return nil, fmt.Errorf("evaluating digits: %s", diags.Error())
		}
		n, _ := val.AsBigFloat().Int64()
		policy.Digits = int(n)
	}

	if attr, exists := content.Attributes["symbols"]; exists {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			return nil, fmt.Errorf("evaluating symbols: %s", diags.Error())
		}
		n, _ := val.AsBigFloat().Int64()
		policy.Symbols = int(n)
	}

	if attr, exists := content.Attributes["symbol_set"]; exists {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			return nil, fmt.Errorf("evaluating symbol_set: %s", diags.Error())
		}
		policy.SymbolCharacters = val.AsString()
	}

	if attr, exists := content.Attributes["no_upper"]; exists {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			return nil, fmt.Errorf("evaluating no_upper: %s", diags.Error())
		}
		policy.NoUpper = val.True()
	}

	if attr, exists := content.Attributes["allow_repeat"]; exists {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			return nil, fmt.Errorf("evaluating allow_repeat: %s", diags.Error())
		}
		b := val.True()
		policy.AllowRepeat = &b
	}

	return &policy, nil
}

// secretBlockSchema defines the schema for secret blocks (v2.0 format)
var secretBlockSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "mount"},
		{Name: "path", Required: true},
		{Name: "version"},
		{Name: "prune"},
		{Name: "enabled"},
	},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "content"},
	},
}

// parseSecretBlock parses a secret block (v2.0 format with content {} block)
func parseSecretBlock(block *hcl.Block, name string, evalCtx *hcl.EvalContext) (*SecretBlock, error) {
	secret := &SecretBlock{
		Name:    name,
		Content: make(map[string]Value),
	}

	bodyContent, bodyDiags := block.Body.Content(secretBlockSchema)
	if bodyDiags.HasErrors() {
		return nil, fmt.Errorf("%s", bodyDiags.Error())
	}

	// Parse mount attribute (optional)
	if attr, exists := bodyContent.Attributes["mount"]; exists {
		val, valDiags := attr.Expr.Value(evalCtx)
		if valDiags.HasErrors() {
			return nil, fmt.Errorf("evaluating mount: %s", valDiags.Error())
		}
		secret.Mount = val.AsString()
	}

	// Parse path attribute (required)
	if attr, exists := bodyContent.Attributes["path"]; exists {
		val, valDiags := attr.Expr.Value(evalCtx)
		if valDiags.HasErrors() {
			return nil, fmt.Errorf("evaluating path: %s", valDiags.Error())
		}
		secret.Path = val.AsString()
	}

	// Parse version attribute (optional)
	if attr, exists := bodyContent.Attributes["version"]; exists {
		val, valDiags := attr.Expr.Value(evalCtx)
		if valDiags.HasErrors() {
			return nil, fmt.Errorf("evaluating version: %s", valDiags.Error())
		}
		n, _ := val.AsBigFloat().Int64()
		secret.Version = int(n)
	}

	// Parse prune attribute (optional)
	if attr, exists := bodyContent.Attributes["prune"]; exists {
		val, valDiags := attr.Expr.Value(evalCtx)
		if valDiags.HasErrors() {
			return nil, fmt.Errorf("evaluating prune: %s", valDiags.Error())
		}
		secret.Prune = val.True()
	}

	// Parse enabled attribute (optional, defaults to true)
	if attr, exists := bodyContent.Attributes["enabled"]; exists {
		val, valDiags := attr.Expr.Value(evalCtx)
		if valDiags.HasErrors() {
			return nil, fmt.Errorf("evaluating enabled: %s", valDiags.Error())
		}
		enabled := val.True()
		secret.Enabled = &enabled
	}

	// Parse content block (required)
	var contentBlock *hcl.Block
	for _, b := range bodyContent.Blocks {
		if b.Type == "content" {
			if contentBlock != nil {
				return nil, fmt.Errorf("only one content block allowed per secret")
			}
			contentBlock = b
		}
	}

	if contentBlock == nil {
		return nil, fmt.Errorf("content block is required")
	}

	// Parse all attributes in the content block as secret key-value pairs
	contentAttrs, attrDiags := contentBlock.Body.JustAttributes()
	if attrDiags.HasErrors() {
		return nil, fmt.Errorf("parsing content block: %s", attrDiags.Error())
	}

	for keyName, attr := range contentAttrs {
		val, valDiags := attr.Expr.Value(evalCtx)
		if valDiags.HasErrors() {
			return nil, fmt.Errorf("evaluating %s: %s", keyName, valDiags.Error())
		}

		value, err := ctyValueToValue(val)
		if err != nil {
			return nil, fmt.Errorf("converting %s: %w", keyName, err)
		}
		secret.Content[keyName] = value
	}

	if len(secret.Content) == 0 {
		return nil, fmt.Errorf("content block must contain at least one key")
	}

	return secret, nil
}

// ctyValueToValue converts a cty.Value to our Value type
func ctyValueToValue(val cty.Value) (Value, error) {
	// If it's a string, it's a static value
	if val.Type() == cty.String {
		return Value{
			Type:   ValueTypeStatic,
			Static: val.AsString(),
		}, nil
	}

	// If it's our marker object, decode it
	if val.Type().IsObjectType() {
		valMap := val.AsValueMap()

		typeStr := valMap["_type"].AsString()
		strategyStr := valMap["_strategy"].AsString()

		v := Value{
			Strategy: Strategy(strategyStr),
		}

		switch typeStr {
		case "generate":
			v.Type = ValueTypeGenerate

			// Parse password policy if any custom values set
			length, _ := valMap["_length"].AsBigFloat().Int64()
			digits, _ := valMap["_digits"].AsBigFloat().Int64()
			symbols, _ := valMap["_symbols"].AsBigFloat().Int64()
			symbolSet := valMap["_symbol_set"].AsString()
			noUpper := valMap["_no_upper"].True()
			allowRepeat := valMap["_allow_repeat"].True()

			// Only set policy if any non-default values
			if length > 0 || digits >= 0 || symbols >= 0 || symbolSet != "" || noUpper || !allowRepeat {
				policy := &PasswordPolicy{
					Digits:  -1, // sentinel: not set
					Symbols: -1, // sentinel: not set
				}
				if length > 0 {
					policy.Length = int(length)
				}
				if digits >= 0 {
					policy.Digits = int(digits)
				}
				if symbols >= 0 {
					policy.Symbols = int(symbols)
				}
				if symbolSet != "" {
					policy.SymbolCharacters = symbolSet
				}
				policy.NoUpper = noUpper
				policy.AllowRepeat = &allowRepeat
				v.Generate = policy
			}

		case "json":
			v.Type = ValueTypeJSON
			v.URL = valMap["_url"].AsString()
			v.Query = valMap["_query"].AsString()

		case "yaml":
			v.Type = ValueTypeYAML
			v.URL = valMap["_url"].AsString()
			v.Query = valMap["_query"].AsString()

		case "raw":
			v.Type = ValueTypeRaw
			v.URL = valMap["_url"].AsString()

		case "vault":
			v.Type = ValueTypeVault
			v.VaultPath = valMap["_vault_path"].AsString()
			v.VaultKey = valMap["_vault_key"].AsString()

		case "command":
			v.Type = ValueTypeCommand
			v.Command = valMap["_command"].AsString()

		case "bcrypt":
			v.Type = ValueTypeBcrypt
			cost, _ := valMap["_cost"].AsBigFloat().Int64()
			v.Bcrypt = &BcryptConfig{
				FromKey: valMap["_from"].AsString(),
				Cost:    int(cost),
			}

		case "argon2":
			v.Type = ValueTypeArgon2
			memory, _ := valMap["_memory"].AsBigFloat().Int64()
			iterations, _ := valMap["_iterations"].AsBigFloat().Int64()
			parallelism, _ := valMap["_parallelism"].AsBigFloat().Int64()
			// Validate bounds for safe conversion
			if memory < 0 || memory > 0xFFFFFFFF {
				return Value{}, fmt.Errorf("argon2 memory out of range: %d", memory)
			}
			if iterations < 0 || iterations > 0xFFFFFFFF {
				return Value{}, fmt.Errorf("argon2 iterations out of range: %d", iterations)
			}
			if parallelism < 0 || parallelism > 255 {
				return Value{}, fmt.Errorf("argon2 parallelism out of range: %d", parallelism)
			}
			v.Argon2 = &Argon2Config{
				FromKey:     valMap["_from"].AsString(),
				Variant:     valMap["_variant"].AsString(),
				Memory:      uint32(memory),     // #nosec G115 -- bounds checked above
				Iterations:  uint32(iterations), // #nosec G115 -- bounds checked above
				Parallelism: uint8(parallelism), // #nosec G115 -- bounds checked above
			}

		case "pbkdf2":
			v.Type = ValueTypePbkdf2
			iterations, _ := valMap["_iterations"].AsBigFloat().Int64()
			v.Pbkdf2 = &Pbkdf2Config{
				FromKey:    valMap["_from"].AsString(),
				Variant:    valMap["_variant"].AsString(),
				Iterations: int(iterations),
				Encoding:   valMap["_encoding"].AsString(),
			}

		case "sha1_htpasswd":
			v.Type = ValueTypeSha1Htpasswd
			v.Sha1Htpasswd = &Sha1HtpasswdConfig{
				FromKey:         valMap["_from"].AsString(),
				Username:        valMap["_username"].AsString(),
				UsernameFromKey: valMap["_username_from"].AsString(),
			}

		default:
			return Value{}, fmt.Errorf("unknown value type: %s", typeStr)
		}

		return v, nil
	}

	return Value{}, fmt.Errorf("unsupported value type: %s", val.Type().FriendlyName())
}

// applyDefaults applies default values to the config
func applyDefaults(cfg *Config) {
	// Apply default mount if not set
	if cfg.Defaults.Mount == "" {
		cfg.Defaults.Mount = "secret"
	}

	// Apply strategy defaults if not set
	if cfg.Defaults.Strategy == (StrategyDefaults{}) {
		cfg.Defaults.Strategy = DefaultStrategyDefaults()
	}

	// Apply password policy defaults
	defaults := DefaultPasswordPolicy()
	if cfg.Defaults.Generate.Length == 0 {
		cfg.Defaults.Generate.Length = defaults.Length
	}
	if cfg.Defaults.Generate.Digits < 0 {
		cfg.Defaults.Generate.Digits = defaults.Digits
	}
	if cfg.Defaults.Generate.Symbols < 0 {
		cfg.Defaults.Generate.Symbols = defaults.Symbols
	}
	if cfg.Defaults.Generate.SymbolCharacters == "" {
		cfg.Defaults.Generate.SymbolCharacters = defaults.SymbolCharacters
	}
	if cfg.Defaults.Generate.AllowRepeat == nil {
		cfg.Defaults.Generate.AllowRepeat = defaults.AllowRepeat
	}

	// Apply defaults to each secret block
	for name, block := range cfg.Secrets {
		// Apply default mount
		if block.Mount == "" {
			block.Mount = cfg.Defaults.Mount
		}
		// Apply default version (0 means auto-detect)
		if block.Version == 0 && cfg.Defaults.Version != 0 {
			block.Version = cfg.Defaults.Version
		}
		cfg.Secrets[name] = block
	}
}

// detectHashCycles checks for circular references and missing references in hash functions
func detectHashCycles(name string, content map[string]Value) error {
	// Build dependency map: key -> key it references (for hash functions only)
	deps := make(map[string]string)
	for key, val := range content {
		var fromKey string
		switch val.Type {
		case ValueTypeBcrypt:
			if val.Bcrypt != nil {
				fromKey = val.Bcrypt.FromKey
			}
		case ValueTypeArgon2:
			if val.Argon2 != nil {
				fromKey = val.Argon2.FromKey
			}
		case ValueTypePbkdf2:
			if val.Pbkdf2 != nil {
				fromKey = val.Pbkdf2.FromKey
			}
		case ValueTypeSha1Htpasswd:
			if val.Sha1Htpasswd != nil {
				fromKey = val.Sha1Htpasswd.FromKey
				// Also validate username_from reference
				if val.Sha1Htpasswd.UsernameFromKey != "" {
					if _, exists := content[val.Sha1Htpasswd.UsernameFromKey]; !exists {
						return fmt.Errorf("secret %q: key %q references non-existent key %q via username_from", name, key, val.Sha1Htpasswd.UsernameFromKey)
					}
				}
			}
		}
		if fromKey != "" {
			deps[key] = fromKey
		}
	}

	// Check that all referenced keys exist
	for key, fromKey := range deps {
		if _, exists := content[fromKey]; !exists {
			return fmt.Errorf("secret %q: key %q references non-existent key %q", name, key, fromKey)
		}
	}

	// Check for cycles by following reference chains
	for startKey := range deps {
		visited := make(map[string]bool)
		current := startKey
		for {
			if visited[current] {
				return fmt.Errorf("secret %q: circular reference detected starting from key %q", name, startKey)
			}
			visited[current] = true
			next, hasNext := deps[current]
			if !hasNext {
				break
			}
			current = next
		}
	}

	return nil
}

// validate validates the configuration
func validate(cfg *Config) error {
	if len(cfg.Secrets) == 0 {
		return fmt.Errorf("no secrets defined")
	}

	// Validate default generate policy
	{
		policy := cfg.Defaults.Generate
		minRequired := policy.Digits + policy.Symbols
		if !policy.NoUpper {
			minRequired++ // At least one uppercase
		}
		if policy.Length < minRequired {
			return fmt.Errorf("defaults.generate: length %d is too small for %d digits + %d symbols",
				policy.Length, policy.Digits, policy.Symbols)
		}
	}

	// Track mount+path combinations for uniqueness check
	fullPaths := make(map[string]string) // fullPath -> block name

	for name, block := range cfg.Secrets {
		if block.Path == "" {
			return fmt.Errorf("secret %q: path is required", name)
		}

		if len(block.Content) == 0 {
			return fmt.Errorf("secret %q: content block must contain at least one key", name)
		}

		if block.Version != 0 && block.Version != 1 && block.Version != 2 {
			return fmt.Errorf("secret %q: version must be 1 or 2 (or 0 for auto)", name)
		}

		// Check for unique mount+path combinations
		fullPath := block.FullPath()
		if existingName, exists := fullPaths[fullPath]; exists {
			return fmt.Errorf("secret %q: duplicate path %q (already defined by %q)", name, fullPath, existingName)
		}
		fullPaths[fullPath] = name

		// Check for hash function reference cycles and missing references
		if err := detectHashCycles(name, block.Content); err != nil {
			return err
		}

		// Validate generate policies
		for key, val := range block.Content {
			if val.Type == ValueTypeGenerate && val.Generate != nil {
				policy := val.Generate
				if policy.Length > 0 && policy.Length < 1 {
					return fmt.Errorf("secret %q key %q: length must be at least 1", name, key)
				}

				digits := policy.Digits
				if digits < 0 {
					digits = cfg.Defaults.Generate.Digits
				}
				symbols := policy.Symbols
				if symbols < 0 {
					symbols = cfg.Defaults.Generate.Symbols
				}
				length := policy.Length
				if length == 0 {
					length = cfg.Defaults.Generate.Length
				}

				minRequired := digits + symbols
				if !policy.NoUpper {
					minRequired++ // At least one uppercase
				}
				if length < minRequired {
					return fmt.Errorf("secret %q key %q: length %d is too small for %d digits + %d symbols",
						name, key, length, digits, symbols)
				}
			}
		}
	}

	return nil
}

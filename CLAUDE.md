# VSG - Vault Secrets Generator

## Project Overview

A lightweight, cloud-agnostic CLI tool that generates and populates secrets in HashiCorp Vault from various sources including remote files (Terraform state, configs), generated passwords, commands, and static values.

**Primary use cases:**
- Extract values from remote JSON/YAML files (S3, GCS, Azure, local) and write them to Vault
- Generate secrets with configurable password policies
- Run commands to generate values (e.g., password hashing)
- Copy secrets between Vault paths
- Declarative HCL configuration for GitOps workflows

## Tech Stack

- **Language:** Go 1.25+
- **Target:** Single static binary, minimal dependencies
- **Container:** Alpine-based, <20MB final image

## Project Structure

```
vault-secrets-generator/
├── main.go                         # CLI entrypoint using cobra
├── internal/
│   ├── command/                    # CLI command implementations
│   │   ├── root.go                 # Root command and global flags
│   │   ├── apply.go                # Apply command
│   │   ├── delete.go               # Delete command
│   │   ├── diff.go                 # Diff command
│   │   └── version.go              # Version command
│   ├── config/
│   │   ├── config.go               # HCL config parsing
│   │   └── types.go                # Config structs
│   ├── fetcher/
│   │   ├── fetcher.go              # Fetcher interface
│   │   ├── s3.go                   # S3 backend
│   │   ├── awssm.go                # AWS Secrets Manager backend (awssm://)
│   │   ├── gcs.go                  # GCS backend
│   │   ├── azure.go                # Azure Blob Storage backend
│   │   └── local.go                # Local file backend
│   ├── parser/
│   │   └── parser.go               # JSON/YAML parser with jq/yq syntax
│   ├── generator/
│   │   └── password.go             # Password generation with policies
│   ├── vault/
│   │   ├── client.go               # Vault client wrapper
│   │   └── writer.go               # KV v1/v2 write operations
│   └── engine/
│       ├── reconcile.go            # Main reconciliation logic
│       └── diff.go                 # Diff/dry-run logic
├── helm/
│   └── vault-secrets-generator/    # Helm chart
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
├── examples/
│   └── config.hcl                  # Example HCL configuration
├── .github/
│   └── workflows/                  # CI/CD workflows
├── .goreleaser.yaml                # Release automation
├── .golangci.yaml                  # Linter configuration
├── Makefile                        # Build, test, lint targets
├── Dockerfile                      # Multi-stage build
├── go.mod
├── go.sum
├── LICENSE
├── README.md
└── CLAUDE.md
```

## Configuration Format

The tool uses a declarative HCL configuration (v2.0 format):

```hcl
vault {
  address = "https://vault.example.com"

  auth {
    method = "kubernetes"
    role   = "vsg"
  }
}

defaults {
  mount   = "secret"   # default mount if not specified per-secret
  version = 2          # KV version: 1 or 2, auto-detect if omitted

  strategy {
    generate = "create"
    json     = "update"
    yaml     = "update"
    raw      = "update"
    static   = "update"
    command  = "update"
    vault    = "update"
  }

  generate {
    length     = 32
    digits     = 5
    symbols    = 5
    symbol_set = "-_$@"
    no_upper   = false
  }
}

secret "dev-app" {
  path  = "${env(\"ENV\")}/app"  # path supports interpolation
  prune = true

  content {
    api_key     = generate()
    jwt_secret  = generate({length = 64, symbols = 0})
    db_host     = json("s3://bucket/dev/terraform.tfstate", ".outputs.db_host.value")
    db_port     = "5432"
    config_host = yaml("gcs://bucket/config.yaml", ".database.host")
    ssh_key     = raw("s3://bucket/keys/deploy.pem")
    shared_key  = vault("secret/shared", "api_key")
    caddy_hash  = command("caddy hash-password --plaintext mypassword")

    # Per-key strategy override
    special     = generate({length = 64, strategy = "update"})
  }
}
```

One secret block = one Vault path = multiple key-value pairs inside.

## Value Types (HCL Functions)

| Type | Syntax | Example |
|------|--------|---------|
| Static | `key = "value"` | `db_port = "5432"` |
| Generate | `key = generate()` | `api_key = generate()` |
| Generate (custom) | `key = generate({...})` | `jwt_secret = generate({length = 64, symbols = 0})` |
| JSON | `key = json(url, query)` | `db_host = json("s3://...", ".outputs.db_host.value")` |
| YAML | `key = yaml(url, query)` | `config = yaml("gcs://...", ".database.host")` |
| Raw | `key = raw(url)` | `ssh_key = raw("s3://bucket/key.pem")` |
| Vault | `key = vault(path, key)` | `shared = vault("secret/shared", "api_key")` |
| Command | `key = command(cmd)` | `hash = command("caddy hash-password ...")` |
| SHA1 htpasswd | `key = sha1_htpasswd({from, username})` | `htpasswd = sha1_htpasswd({from = "password", username = "admin"})` |

All functions support optional `strategy` parameter via object literal:

```hcl
db_host = json("s3://...", ".outputs.db_host.value", {strategy = "create"})
ssh_key = raw("s3://bucket/key.pem", {strategy = "create"})
```

## URL Schemes

For `json()`, `yaml()`, `raw()` functions:

| Scheme | Source |
|--------|--------|
| `s3://bucket/path` | AWS S3 |
| `gcs://bucket/path` | Google Cloud Storage |
| `az://container/path` | Azure Blob Storage |
| `/path/to/file` | Local file (no scheme) |

## Generate Options

| Option | Default | Description |
|--------|---------|-------------|
| `length` | 32 | Total password length |
| `digits` | 5 | Minimum digit characters |
| `symbols` | 5 | Minimum symbol characters |
| `symbol_set` | `-_$@` | Allowed symbol characters |
| `no_upper` | false | Exclude uppercase letters |

## Environment Variables: env() Function

The `env()` function retrieves values from environment variables or `--var` CLI flags:

```hcl
secret "secret/dev/app" {
  db_host = json("s3://my-bucket/dev/terraform.tfstate", ".outputs.db_host.value")
  region  = env("REGION")
}
```

Note: Template interpolation (`${...}`) is not supported in HCL block labels or string values. Use `env()` for individual values.

Usage:

```bash
# From environment
ENV=dev BUCKET=my-terraform-state vsg apply

# From CLI (overrides environment)
vsg apply --var ENV=dev --var BUCKET=my-terraform-state

# Mixed (CLI wins)
ENV=prod vsg apply --var ENV=dev   # uses "dev"
```

**Priority:** `--var` CLI flag > environment variable

## Strategies

| Strategy | Key missing | Key exists, same value | Key exists, different value |
|----------|-------------|------------------------|----------------------------|
| `create` | Create | Skip | Skip |
| `update` | Create | Skip | Update |

### Default Strategies

| Value type | Default strategy | Reasoning |
|------------|-----------------|-----------|
| `generate` | `create` | Don't regenerate existing passwords |
| `json` | `update` | Keep in sync with source |
| `yaml` | `update` | Keep in sync with source |
| `raw` | `update` | Keep in sync with source |
| `static` | `update` | Update if changed |
| `command` | `update` | Re-run and update |
| `vault` | `update` | Keep in sync with source |
| `sha1_htpasswd` | `update` | Keep in sync with source key |

Per-key override via `strategy` parameter in any function.

## Prune (Per Secret)

| `prune` | Key in config | Key in Vault only |
|---------|---------------|-------------------|
| `false` (default) | Create/Update | Warn, keep |
| `true` | Create/Update | Delete |

## CLI Interface

```bash
vsg apply                                  # apply config to vault
vsg apply --config config.hcl              # specify config file
vsg apply --dry-run                        # preview changes
vsg apply --force                          # regenerate all passwords
vsg apply --var ENV=dev --var REGION=us    # pass variables

vsg diff                                   # show diff
vsg diff --config config.hcl

# Delete entire secret
vsg delete secret/path                     # soft delete (default, recoverable)
vsg delete secret/path --hard              # destroy version data permanently
vsg delete secret/path --full              # remove all versions + metadata

# Delete specific keys (writes new version without those keys)
vsg delete secret/path --keys key1,key2

vsg version
```

### Delete Flags (KV v2)

| VSG Flag | Vault Equivalent | Effect |
|----------|------------------|--------|
| (default) | `vault kv delete` | Soft delete, recoverable via `vault kv undelete` |
| `--hard` | `vault kv destroy` | Permanently destroy version data, metadata remains |
| `--full` | `vault kv metadata delete` | Remove all versions and metadata completely |

**Note:** `--hard` and `--full` only apply to KV v2. KV v1 delete is always permanent.

### Exit Codes

- `0` - Success, all secrets synced
- `1` - Configuration error
- `2` - Vault connection/auth error
- `3` - Source file fetch error
- `4` - Partial failure (some secrets failed)

## Vault Auto-Detection

VSG auto-detects KV v1 vs v2 by querying `/sys/mounts`. User specifies path (e.g., `secret/dev`), VSG determines engine version automatically.

## Core Logic

### Reconciliation Flow

1. Parse and validate config HCL
2. Resolve all `env()` function calls
3. For each secret block:
   a. Connect to Vault at specified path
   b. Read current secrets (if exist)
   c. For each key in data:
      - If `json()`/`yaml()`/`raw()`: fetch file, extract value
      - If `generate()`: generate password based on strategy
      - If `vault()`: read from source Vault path
      - If `command()`: run command and capture output
      - If static: use value as-is
   d. Apply strategy (create vs update) per key
   e. Write changes to Vault (unless --dry-run)
   f. If `prune = true`: delete keys in Vault not in config
4. Report results

### Important Behaviors

1. **Strategy-based reconciliation:**
   - `create` strategy: only creates new keys, never updates existing
   - `update` strategy: creates new keys and updates changed values
   - `--force` flag: regenerate all passwords regardless of strategy

2. **Source file caching:**
   - Cache fetched files during a single run
   - Multiple secrets from same source file = one fetch

3. **Error handling:**
   - Continue on individual secret failures
   - Report all errors at end
   - Detailed error messages with context

## Vault Authentication

Supported auth methods:
- **Token** - `VAULT_TOKEN` env var or config
- **Kubernetes** - ServiceAccount JWT (for pods)
- **AppRole** - `role_id`/`secret_id` (for CI/CD, non-K8s apps)

## Environment Variables

```bash
VAULT_ADDR          # Vault server address
VAULT_TOKEN         # Vault token (for token auth)
VAULT_NAMESPACE     # Vault namespace (enterprise)
AWS_REGION          # AWS region for S3
AWS_PROFILE         # AWS profile (optional)
GOOGLE_APPLICATION_CREDENTIALS  # GCP service account (for GCS)
AZURE_STORAGE_ACCOUNT           # Azure storage account
VSG_CONFIG          # Default config file path
```

## Testing

Run tests with `go test ./...`. Integration tests require a running Vault server with `VAULT_ADDR` and `VAULT_TOKEN` set.

## Code Style

- Use standard Go formatting (`gofmt`)
- Keep functions small and focused
- Comprehensive error wrapping with context
- Use `context.Context` for cancellation
- Structured logging (consider `slog` from stdlib)

## Git Conventions

- Stage files explicitly with `git add <file>`
- Commit with `git commit -m 'message'`
- Can use `git commit -am 'message'` for tracked files
- **Never use `git add -A`** - always stage files explicitly

### Commit Message Prefixes

Use these prefixes for proper release note categorization:

| Prefix | Use for | Release Section |
|--------|---------|-----------------|
| `feat:` | New features | Features |
| `fix:` | Bug fixes | Bug Fixes |
| `docs:` | Documentation only | Documentation |
| `refactor:` | Code refactoring | Other |
| `test:` | Adding/updating tests | *excluded* |
| `chore:` | Maintenance tasks | Infrastructure |
| `ci:` | CI/CD changes | Infrastructure |

**Special patterns:**
- "Update dependencies" / "bump" → Dependencies section
- "Update Go" / Dockerfile / Helm → Infrastructure section
- "breaking" anywhere → ⚠️ Breaking Changes section

## Kubernetes Deployment

Helm chart available at `helm/vault-secrets-generator/`. Typically deployed as a Job with Kubernetes auth.

## Non-Goals (Out of Scope)

- Secret rotation scheduling (use external scheduler)
- Vault policy management
- Multi-Vault support (single Vault per config)
- Webhooks or event-driven sync
- Web UI

## Current Status

**Version:** v2.2.0

### Implemented Features
- [x] HCL config parsing with custom functions
- [x] `env()` function for environment variables with CLI `--var` override
- [x] `generate()`, `json()`, `yaml()`, `raw()`, `vault()`, `command()` functions
- [x] Strategy system (`create` vs `update`) per value type
- [x] Per-key strategy override via object literal syntax
- [x] Prune logic per secret block
- [x] CLI `--var` flag for variable override
- [x] Path-based delete command with `--hard`, `--full`, `--keys` flags
- [x] Password generator with configurable policies
- [x] Local file fetcher (tested)
- [x] S3 fetcher with AWS SDK v2 (tested with json/yaml/raw extraction)
- [x] Vault client with token auth, KV v1/v2 auto-detection (tested)
- [x] Reconciliation engine + dry-run (tested)
- [x] CLI with cobra
- [x] Helm chart
- [x] Dockerfile
- [x] GitHub Actions CI/CD
- [x] goreleaser configuration with auto-release
- [x] Command execution with multiline output (tested)
- [x] Homebrew tap (`brew install pavlenkoa/tap/vsg`)
- [x] **v2.0.0 config structure** with `content {}` block and path interpolation
- [x] **v2.1.0 Secret filtering**: `enabled` attribute and `--target`/`--exclude` flags
- [x] **v2.1.0 Config-based delete**: delete command with `--config`, `--target`, `--all`, `--exclude`

- [x] **v2.2.0 Password hashing functions**: `bcrypt()`, `argon2()`, `pbkdf2()` with referential values
- [x] **v2.3.0 SHA1 htpasswd function**: `sha1_htpasswd()` with `username`/`username_from` support

### Planned
- [ ] GCS fetcher
- [ ] Azure Blob Storage fetcher
- [ ] Kubernetes auth testing
- [ ] AppRole auth testing

## Password Hashing Functions

Native password hashing functions that can reference other keys in the same secret block. This enables generating a password and its hash in a single declarative config.

### Syntax

```hcl
secret "authelia" {
  path = "authelia"

  content {
    # Generate a random password
    admin_password = generate({length = 32})

    # Hash the generated password with argon2id
    admin_password_hash = argon2({from = "admin_password"})

    # Generate OIDC client secret and its PBKDF2 hash
    oidc_client_plaintext = generate({length = 64, symbols = 0})
    oidc_client_secret = pbkdf2({from = "oidc_client_plaintext", variant = "sha512"})

    # bcrypt example
    api_key = generate()
    api_key_hash = bcrypt({from = "api_key", cost = 12})

    # SHA1 htpasswd example
    push_user     = "promtail"
    push_password = generate({length = 32, symbols = 0})
    htpasswd      = sha1_htpasswd({from = "push_password", username = "promtail"})
    # Or reference username from another key:
    htpasswd_ref  = sha1_htpasswd({from = "push_password", username_from = "push_user"})
  }
}
```

### Supported Algorithms

| Function | Output Format | Use Cases |
|----------|---------------|-----------|
| `bcrypt({from, cost})` | `$2a$cost$salt...hash` | Most web frameworks (Rails, Django, Node.js) |
| `argon2({from, variant, memory, iterations, parallelism})` | `$argon2id$v=19$m=65536,t=3,p=4$salt$hash` | Authelia, Bitwarden, modern apps |
| `pbkdf2({from, variant, iterations, encoding})` | `$pbkdf2-sha512$iterations$salt$hash` | Enterprise/FIPS compliance, Authelia OIDC |
| `sha1_htpasswd({from, username/username_from})` | `username:{SHA}base64hash` | htpasswd basic auth (kgateway, Apache, nginx) |

### Default Parameters

| Algorithm | Parameter | Default |
|-----------|-----------|---------|
| bcrypt | cost | 12 |
| argon2 | variant | id |
| argon2 | memory | 65536 (64MB) |
| argon2 | iterations | 3 |
| argon2 | parallelism | 4 |
| pbkdf2 | variant | sha512 |
| pbkdf2 | iterations | 310000 |
| pbkdf2 | encoding | phc |
| sha1_htpasswd | (none) | No tunable parameters |

### SHA1 Htpasswd Options

| Option | Required | Description |
|--------|----------|-------------|
| `from` | Yes | Key name to hash |
| `username` | One of | Static username string (mutually exclusive with `username_from`) |
| `username_from` | these | Key name to read username from (mutually exclusive with `username`) |

### Strategy Behavior

Hash functions use `update` strategy by default (like other derived values):
- Uses **verification** to determine if update is needed (not string comparison)
- If the existing hash verifies against the source password, no update needed
- If the hash is stale (doesn't verify), regenerate with new salt
- Use `--force` flag to regenerate all passwords and hashes
- Can override with `strategy = "create"` to never update existing hashes

### Behavior Notes

- **Cycle detection**: Circular references are detected at parse time
- **Missing references**: Error at parse time if `from` references a non-existent key
- **PHC format**: All hashes use Password Hashing Competition string format
- **PBKDF2 encoding**: Two base64 encodings available via `encoding` parameter:
  - `"phc"` (default) — standard base64 alphabet (`+/`), no padding. PHC spec compliant.
  - `"crypt"` — crypt(3)-adapted alphabet (`./`), no padding. Compatible with Authelia and go-crypt.
- **Dependency ordering**: Source keys are always resolved before dependent hashes

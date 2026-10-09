# VSG - Vault Secrets Generator

> **Vibecoded with [Claude Code](https://github.com/anthropics/claude-code)**

A lightweight, cloud-agnostic CLI tool that generates and populates secrets in HashiCorp Vault from various sources including remote files, generated passwords, commands, and static values.

## Features

- **HCL Configuration**: Declarative HCL-based configuration with custom functions
- **Dynamic Paths**: Use `${env("VAR")}` interpolation in secret paths
- **Remote File Integration**: Extract values from JSON/YAML files stored in S3, GCS, or local filesystem
- **Password Generation**: Generate secure passwords with configurable policies
- **Command Execution**: Generate values by running shell commands
- **Copy Between Paths**: Copy secrets between Vault paths using `vault()` function
- **Strategy System**: Control when values are created vs updated with `create` and `update` strategies
- **Prune Support**: Optionally delete unmanaged keys from Vault paths
- **Secret Filtering**: Target or exclude specific secrets with `--target`/`--exclude` flags
- **Idempotent Operations**: Generated passwords are preserved unless strategy or force flag overrides
- **Dry-Run Support**: Preview changes before applying them
- **Multiple Auth Methods**: Token, Kubernetes, and AppRole authentication

## Installation

### Docker

```bash
docker pull proteantecs/vault-secrets-generator:latest
```

### From Source

```bash
go install github.com/pavlenkoa/vault-secrets-generator@latest
```

### Build from Source

```bash
git clone https://github.com/pavlenkoa/vault-secrets-generator.git
cd vault-secrets-generator
go build -o vsg .
```

## Quick Start

1. Create a configuration file `config.hcl`:

```hcl
vault {
  address = "https://vault.example.com"
  auth {
    method = "token"
  }
}

secret "dev-database" {
  path = "dev/database"

  content {
    host     = json("s3://terraform-state/dev/rds.tfstate", ".outputs.endpoint.value")
    password = generate()
    port     = "5432"
  }
}

secret "dev-app" {
  path = "dev/app"

  content {
    api_key     = generate()
    environment = "dev"
  }
}
```

2. Set up Vault credentials:

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="hvs.xxxxx"
```

3. Preview changes:

```bash
vsg diff --config config.hcl
```

4. Apply secrets:

```bash
vsg apply --config config.hcl
```

## CLI Reference

### Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--config` | `-c` | Config file path (or set `VSG_CONFIG` env var) |
| `--var` | | Set variable KEY=VALUE (can be repeated) |
| `--verbose` | `-v` | Enable verbose output |

### Commands

#### `vsg apply`

Apply secrets to Vault.

```bash
vsg apply --config config.hcl [flags]
```

| Flag | Short | Description |
|------|-------|-------------|
| `--dry-run` | | Show what would be done without making changes |
| `--force` | | Force regeneration of generated secrets |
| `--target` | `-t` | Target specific secrets by label (comma-separated or repeated) |
| `--exclude` | `-e` | Exclude secrets by label (comma-separated or repeated) |
| `--var KEY=VALUE` | | Set variable (can be repeated) |

Examples:

```bash
# Apply all secrets
vsg apply --config config.hcl

# Apply specific secrets only
vsg apply --config config.hcl --target prod-app
vsg apply --config config.hcl -t prod-app -t prod-db

# Apply all except specific secrets
vsg apply --config config.hcl --exclude broken-secret
vsg apply --config config.hcl -e broken -e legacy
```

#### `vsg diff`

Show differences between current and desired state.

```bash
vsg diff --config config.hcl [flags]
```

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Output format: `text` (default) or `json` |
| `--target` | `-t` | Target specific secrets by label (comma-separated or repeated) |
| `--exclude` | `-e` | Exclude secrets by label (comma-separated or repeated) |
| `--var KEY=VALUE` | | Set variable (can be repeated) |

#### `vsg delete`

Delete secrets from Vault. Supports two modes:

**Path mode**: Delete a secret at a specific Vault path directly.

```bash
vsg delete <path> [flags]
```

**Config mode**: Delete secrets defined in a config file.

```bash
vsg delete --config <file> (--target <labels> | --all) [flags]
```

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | `-f` | Skip confirmation prompt |
| `--hard` | | Destroy version data permanently (KV v2 only) |
| `--full` | | Remove all versions and metadata (KV v2 only) |
| `--keys` | | Comma-separated list of keys to delete (path mode only) |
| `--target` | `-t` | Target secrets by label (config mode, comma-separated or repeated) |
| `--exclude` | `-e` | Exclude secrets by label (config mode, comma-separated or repeated) |
| `--all` | | Delete all secrets in config (config mode) |

Examples:

```bash
# Path mode - soft delete (recoverable in KV v2)
vsg delete secret/myapp

# Path mode - delete specific keys only
vsg delete secret/myapp --keys old_key,deprecated_key

# Path mode - destroy version data permanently
vsg delete secret/myapp --hard

# Path mode - remove all versions and metadata
vsg delete secret/myapp --full

# Config mode - delete specific secrets by label
vsg delete --config config.hcl --target prod-app
vsg delete --config config.hcl --target prod-app,prod-db --hard

# Config mode - delete all secrets in config
vsg delete --config config.hcl --all

# Config mode - delete all except specific ones
vsg delete --config config.hcl --all --exclude keep-this --force
```

#### `vsg version`

Print version information.

```bash
vsg version
```

## Configuration

### Secret Block Structure

Each secret block defines a group of key-value pairs to write to a single Vault path:

```hcl
secret "<name>" {
  mount   = "secret"           # Optional: KV mount path (default: from defaults.mount)
  path    = "myapp/config"     # Required: Path within the mount
  version = 2                  # Optional: KV version 1 or 2 (default: auto-detect)
  prune   = false              # Optional: Delete unmanaged keys (default: false)
  enabled = true               # Optional: Process this secret (default: true)

  content {
    # Key-value pairs go here
    api_key  = generate()
    db_host  = "localhost"
  }
}
```

#### The `enabled` Attribute

Set `enabled = false` to skip a secret block during apply/diff operations:

```hcl
secret "prod-app" {
  enabled = true  # Default, can be omitted
  path    = "prod/app"
  content { key = generate() }
}

secret "broken-secret" {
  enabled = false  # VSG will skip this block
  path    = "broken/path"
  content { key = generate() }
}
```

The `--target` flag overrides `enabled = false`, allowing you to run disabled secrets explicitly:

```bash
# This will run broken-secret even though enabled = false
vsg apply --config config.hcl --target broken-secret
```

The `path` attribute supports interpolation:

```hcl
secret "app" {
  path = "${env("ENV")}/app"  # Becomes "prod/app" when ENV=prod

  content {
    key = "value"
  }
}
```

### Full Example

```hcl
# Vault connection settings
vault {
  address = "https://vault.example.com"
  # namespace = "admin"  # Optional, for Vault Enterprise

  auth {
    method = "kubernetes"
    role   = "vsg"
    # mount_path = "kubernetes"  # Optional, defaults to "kubernetes"

    # For token auth:
    # method = "token"
    # token = "hvs.xxx"  # Or use VAULT_TOKEN env var

    # For approle auth:
    # method = "approle"
    # role_id = "xxx"    # Or use VAULT_ROLE_ID env var
    # secret_id = "xxx"  # Or use VAULT_SECRET_ID env var
  }
}

# Default settings for all secrets
defaults {
  mount   = "secret"  # Default KV mount path
  version = 2         # Default KV version (1, 2, or omit for auto-detect)

  # Default strategies per value type
  strategy {
    generate = "create"  # Don't regenerate existing passwords
    json     = "update"  # Keep in sync with source
    yaml     = "update"  # Keep in sync with source
    raw      = "update"  # Keep in sync with source
    static   = "update"  # Update if changed
    command  = "update"  # Re-run and update
    vault    = "update"  # Keep in sync with source
  }

  # Default password generation policy
  generate {
    length     = 32
    digits     = 5
    symbols    = 5
    symbol_set = "-_$@"
    no_upper   = false
  }
}

# Database secrets with dynamic path
secret "dev-database" {
  path  = "${env(\"ENV\")}/database"
  prune = true  # Delete keys in Vault not defined here

  content {
    # Extract from Terraform state file in S3
    host     = json("s3://terraform-state/dev/rds.tfstate", ".outputs.endpoint.value")
    port     = json("s3://terraform-state/dev/rds.tfstate", ".outputs.port.value")
    username = json("s3://terraform-state/dev/rds.tfstate", ".outputs.username.value")

    # Generated password - won't regenerate if exists (create strategy)
    password = generate()

    # Static value
    database = "myapp"
  }
}

# Application secrets with custom mount
secret "dev-app" {
  mount = "kv"  # Override default mount
  path  = "dev/app"

  content {
    # api_key with default policy (32 chars)
    api_key = generate()

    # jwt_secret with custom policy (64 chars, no symbols)
    jwt_secret = generate({length = 64, symbols = 0})

    # webhook_token with custom policy and strategy override
    webhook_token = generate({length = 48, symbols = 0, strategy = "update"})

    # Copy from another Vault path
    shared_key = vault("secret/shared", "api_key")

    # From command execution
    password_hash = command("echo -n 'secret123' | sha256sum | cut -d' ' -f1")

    # Environment value from env() function
    environment = env("ENV")

    # Static values
    log_level = "info"
    version   = "1.2.3"
  }
}

# SSH keys from raw files
secret "dev-ssh" {
  path = "dev/ssh"

  content {
    # Raw file content (no extraction)
    deploy_key = raw("s3://keys/dev/deploy.pem")

    # With create strategy - won't update if key exists
    backup_key = raw("s3://keys/dev/backup.pem", {strategy = "create"})
  }
}

# Config extracted from YAML file
secret "dev-config" {
  path = "dev/config"

  content {
    redis_host = yaml("s3://configs/dev/app.yaml", ".redis.host")
    redis_port = yaml("s3://configs/dev/app.yaml", ".redis.port")
  }
}
```

### Value Types (HCL Functions)

| Type | Syntax | Description |
|------|--------|-------------|
| Static | `key = "value"` | Static string value |
| Generate | `generate()` | Generate password with default policy |
| Generate (custom) | `generate({length = 64, ...})` | Generate with custom policy |
| JSON | `json(url, query)` | Extract from JSON file |
| YAML | `yaml(url, query)` | Extract from YAML file |
| Raw | `raw(url)` | Raw file content |
| AWS Secrets Manager | `aws_sm(secret, key)` | Key of a JSON secret in AWS Secrets Manager |
| Vault | `vault(path, key)` | Copy from another Vault path |
| Command | `command(cmd)` | Execute shell command |
| Env | `env(name)` | Environment variable |
| Bcrypt | `bcrypt({from = "key"})` | Hash value from another key (bcrypt) |
| Argon2 | `argon2({from = "key"})` | Hash value from another key (argon2) |
| PBKDF2 | `pbkdf2({from = "key"})` | Hash value from another key (PBKDF2) |
| SHA1 htpasswd | `sha1_htpasswd({from = "key", username = "user"})` | Generate htpasswd entry in {SHA} format |

All functions support optional strategy parameter via object literal:

```hcl
db_host  = json("s3://...", ".outputs.db_host.value", {strategy = "create"})
ssh_key  = raw("s3://bucket/key.pem", {strategy = "create"})
password = generate({length = 64, strategy = "update"})
```

`aws_sm("vsg/prod/shared", "foo")` is shorthand for `json("awssm://vsg/prod/shared", ".foo")`. It uses the default AWS credential chain (IRSA, env, instance role) and needs `secretsmanager:GetSecretValue` on the secret.

### URL Schemes

For `json()`, `yaml()`, and `raw()` functions:

| Scheme | Source |
|--------|--------|
| `s3://bucket/path` | AWS S3 |
| `awssm://secret-name` | AWS Secrets Manager (secret string) |
| `gcs://bucket/path` | Google Cloud Storage |
| `az://container/path` | Azure Blob Storage |
| `/path/to/file` | Local file (no scheme) |
| `file:///path` | Local file (explicit) |

### Generate Options

| Option | Default | Description |
|--------|---------|-------------|
| `length` | 32 | Total password length |
| `digits` | 5 | Minimum digit characters |
| `symbols` | 5 | Minimum symbol characters |
| `symbol_set` | `-_$@` | Allowed symbol characters |
| `no_upper` | false | Exclude uppercase letters |

### Hash Functions

Hash functions generate password hashes that reference other keys in the same secret block:

```hcl
secret "app" {
  path = "app/auth"

  content {
    admin_password      = generate({length = 32})
    admin_password_hash = argon2({from = "admin_password"})

    api_key             = generate()
    api_key_bcrypt      = bcrypt({from = "api_key", cost = 12})

    oidc_secret         = generate({length = 64, symbols = 0})
    oidc_hash           = pbkdf2({from = "oidc_secret", variant = "sha512"})
  }
}
```

**Bcrypt options:**
| Option | Default | Description |
|--------|---------|-------------|
| `from` | (required) | Key name to hash |
| `cost` | 12 | Bcrypt cost factor (4-31) |

**Argon2 options:**
| Option | Default | Description |
|--------|---------|-------------|
| `from` | (required) | Key name to hash |
| `variant` | `id` | `id` (argon2id) or `i` (argon2i) |
| `memory` | 65536 | Memory in KB (64MB default) |
| `iterations` | 3 | Number of iterations |
| `parallelism` | 4 | Degree of parallelism |

**PBKDF2 options:**
| Option | Default | Description |
|--------|---------|-------------|
| `from` | (required) | Key name to hash |
| `variant` | `sha512` | `sha256` or `sha512` |
| `iterations` | 310000 | Number of iterations |
| `encoding` | `phc` | Base64 encoding: `phc` (standard `+/` alphabet) or `crypt` (crypt(3) `./` alphabet, Authelia compatible) |

**SHA1 htpasswd options:**
| Option | Default | Description |
|--------|---------|-------------|
| `from` | (required) | Key name to hash |
| `username` | (required*) | Static username for the htpasswd entry |
| `username_from` | (required*) | Key name to read username from |

*Exactly one of `username` or `username_from` must be specified.

Output format: `username:{SHA}base64_encoded_sha1_hash`

```hcl
# Static username
htpasswd = sha1_htpasswd({from = "push_password", username = "promtail"})

# Username from another key
htpasswd = sha1_htpasswd({from = "push_password", username_from = "push_user"})
```

Hash functions use **verification** to determine updates - if the existing hash verifies against the current password, no update occurs (avoiding unnecessary secret version bumps).

### Strategies

| Strategy | Key missing | Key exists, same value | Key exists, different value |
|----------|-------------|------------------------|----------------------------|
| `create` | Create | Skip | Skip |
| `update` | Create | Skip | Update |

Default strategies by value type:

| Value type | Default strategy | Reasoning |
|------------|-----------------|-----------|
| `generate` | `create` | Don't regenerate existing passwords |
| `json` | `update` | Keep in sync with source |
| `yaml` | `update` | Keep in sync with source |
| `raw` | `update` | Keep in sync with source |
| `static` | `update` | Update if changed |
| `command` | `update` | Re-run and update |
| `vault` | `update` | Keep in sync with source |
| `bcrypt` | `update` | Keep hash in sync with source key |
| `argon2` | `update` | Keep hash in sync with source key |
| `pbkdf2` | `update` | Keep hash in sync with source key |
| `sha1_htpasswd` | `update` | Keep hash in sync with source key |

### Prune

When `prune = true` is set on a secret block, keys in Vault that are not defined in the config will be deleted.

| `prune` | Key in config | Key in Vault only |
|---------|---------------|-------------------|
| `false` (default) | Create/Update | Warn, keep |
| `true` | Create/Update | Delete |

### Variables with env()

Use the `env()` function to reference environment variables or CLI variables:

```hcl
secret "app" {
  path = "${env(\"ENV\")}/app"  # Dynamic path based on ENV variable

  content {
    region = env("AWS_REGION")
  }
}
```

CLI variables override environment variables:

```bash
# From environment
AWS_REGION=us-east-1 ENV=dev vsg apply

# From CLI (overrides environment)
vsg apply --var AWS_REGION=us-west-2 --var ENV=prod
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VAULT_ADDR` | Vault server address |
| `VAULT_TOKEN` | Vault token (for token auth) |
| `VAULT_NAMESPACE` | Vault namespace (Enterprise) |
| `VAULT_ROLE_ID` | AppRole role ID |
| `VAULT_SECRET_ID` | AppRole secret ID |
| `VSG_CONFIG` | Default config file path |
| `AWS_REGION` | AWS region for S3 |
| `AWS_PROFILE` | AWS profile |
| `GOOGLE_APPLICATION_CREDENTIALS` | GCP service account (for GCS) |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Configuration error |
| 2 | Vault connection/auth error |
| 3 | Source file fetch error |
| 4 | Partial failure (some secrets failed) |

## Kubernetes Deployment

A Helm chart is available at [helm/vault-secrets-generator](helm/vault-secrets-generator/). See [values.yaml](helm/vault-secrets-generator/values.yaml) for configuration options.

## Development

```bash
go test ./...
```

Integration tests require `VAULT_ADDR` and `VAULT_TOKEN` environment variables.

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

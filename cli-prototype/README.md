# PackageInferno CLI

> Shift-left supply chain security for npm packages

A fully type-safe TypeScript CLI wrapper around PackageInferno, designed for integration into development workflows, CI/CD pipelines, and pre-commit hooks.

## 🚀 Features

- **Type-safe commands** - Built with oclif and TypeScript for maximum safety
- **Docker-first** - Automatic container management, no manual setup
- **Multiple output formats** - JSON, SARIF, JUnit XML, console
- **Policy engine** - Define security policies as code
- **CI/CD ready** - Standardized exit codes and report formats
- **Fast** - Parallel scanning with configurable concurrency

## 📦 Installation

```bash
# Global installation
npm install -g @package-inferno/cli

# Or use with npx
npx @package-inferno/cli scan package lodash
```

## 🎯 Quick Start

```bash
# Scan specific packages
inferno scan package lodash express

# Scan from lockfile
inferno scan lockfile package-lock.json

# Fail CI on malicious packages
inferno scan package axios --fail-on malicious --output sarif

# Scan with policy enforcement
inferno scan package react --policy .inferno/policy.yml
```

## 📖 Usage

### Scan Commands

#### Scan Specific Packages

```bash
inferno scan package <packages...> [options]

# Examples:
inferno scan package lodash
inferno scan package lodash@4.17.21 express@4.18.0
inferno scan package react --threshold malicious
inferno scan package axios --output json --fail-on suspicious
```

**Options:**
- `-t, --threshold <level>` - Minimum severity threshold (suspicious|malicious)
- `-o, --output <format>` - Output format (json|sarif|console|junit)
- `--fail-on <level>` - Exit with error on severity level
- `--max-concurrent <n>` - Maximum concurrent scans (default: 5)
- `-c, --config <path>` - Configuration file path
- `-p, --policy <path>` - Policy file path
- `-f, --output-file <path>` - Write output to file
- `-v, --verbose` - Enable verbose logging

#### Scan Lockfile

```bash
inferno scan lockfile <path> [options]

# Examples:
inferno scan lockfile package-lock.json
inferno scan lockfile package-lock.json --compare old.json
inferno scan lockfile package-lock.json --output sarif --fail-on malicious
```

**Options:**
- `--compare <path>` - Compare with previous lockfile (scan only new packages)
- All options from `scan package`

#### Scan Directory

```bash
inferno scan directory <path> [options]

# Examples:
inferno scan directory ./node_modules
inferno scan directory ./node_modules --threshold malicious
```

### Report Commands

```bash
# Generate report from previous scan
inferno report generate --scan-id abc123 --output pdf

# Export findings to external systems
inferno report export --format csv --output findings.csv
```

### Policy Commands

```bash
# Initialize policy file
inferno policy create .inferno/policy.yml

# Validate policy syntax
inferno policy validate .inferno/policy.yml

# Apply policy to scan results
inferno policy apply --results scan-results.json --policy .inferno/policy.yml
```

### Daemon Commands

```bash
# Start background monitoring
inferno daemon start --watch ./package.json

# Check daemon status
inferno daemon status

# Stop daemon
inferno daemon stop
```

### Config Commands

```bash
# Generate default config
inferno config init

# Validate config
inferno config validate .inferno/config.yml

# Show current config
inferno config show
```

## 🔧 Configuration

### CLI Configuration (`.inferno/config.yml`)

```yaml
version: "1.0.0"

docker:
  maxConcurrent: 5
  timeout: 300000  # 5 minutes
  pullPolicy: missing  # always | missing | never
  cleanup: true
  network:
    isolated: true

output:
  format: console
  directory: ./inferno-reports
  verbose: false

cache:
  enabled: true
  directory: ~/.inferno/cache
  ttl: 86400  # 24 hours
```

### Policy Configuration (`.inferno/policy.yml`)

```yaml
version: 1
name: "Production Security Policy"

rules:
  - id: block-malicious
    severity: high
    action: block
    message: "Malicious packages are strictly prohibited"

  - id: warn-suspicious
    severity: medium
    action: warn
    conditions:
      - "score < 15"

  - id: block-c2
    finding: c2_webhook
    action: block
    message: "C2 communication detected"

allowlist:
  packages:
    - name: "legacy-package@1.0.0"
      reason: "Required for legacy systems"
      expires: "2025-12-31"

thresholds:
  suspicious: 7
  malicious: 12

notifications:
  slack:
    webhook: "${SLACK_WEBHOOK_URL}"
    channel: "#security-alerts"
```

## 🔗 CI/CD Integration

### GitHub Actions

```yaml
name: Supply Chain Security

on:
  pull_request:
    paths:
      - 'package-lock.json'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Inferno CLI
        run: npm install -g @package-inferno/cli

      - name: Scan dependencies
        run: |
          inferno scan lockfile package-lock.json \
            --threshold suspicious \
            --output sarif \
            --fail-on malicious

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: inferno-results.sarif
```

### GitLab CI

```yaml
dependency-scan:
  stage: security
  image: node:20
  before_script:
    - npm install -g @package-inferno/cli
  script:
    - inferno scan lockfile package-lock.json --output junit
  artifacts:
    reports:
      junit: inferno-junit.xml
```

### Pre-commit Hook

```bash
#!/bin/bash
if git diff --cached --name-only | grep -q 'package-lock.json'; then
  inferno scan lockfile package-lock.json --fail-on malicious
fi
```

## 📊 Exit Codes

- `0` - Success, no issues found
- `1` - Malicious packages detected
- `2` - Suspicious packages found
- `3` - Policy violation
- `10` - Scan error
- `11` - Configuration error
- `12` - Docker operation failed
- `13` - Network connectivity issue

## 🏗️ Type Safety Features

This CLI is built with maximum type safety:

- ✅ **Zod runtime validation** - All inputs validated at runtime
- ✅ **Strict TypeScript** - `strict: true` with additional checks
- ✅ **Exhaustive switch checks** - Never miss a case
- ✅ **No implicit any** - Every value has a type
- ✅ **Readonly arrays** - Immutable data structures
- ✅ **Branded types** - Prevent primitive obsession

## 🧪 Testing

```bash
# Run unit tests
npm test

# Run with coverage
npm run test:coverage

# Test specific command
npm test -- --grep "scan package"
```

## 📚 Architecture

```
src/
├── commands/           # oclif command definitions
│   ├── scan/
│   ├── report/
│   ├── policy/
│   └── daemon/
├── lib/
│   ├── docker/        # Type-safe Docker API
│   ├── parsers/       # Lockfile/package.json parsers
│   ├── reporters/     # Output formatters
│   └── policy/        # Policy engine
└── types/             # Shared TypeScript types
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md).

## 📄 License

Apache 2.0 - See [LICENSE](LICENSE) for details.

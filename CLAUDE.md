# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Melange is a Go-based CLI tool for building APK packages using declarative YAML pipelines. It's primarily used with apko for creating custom packages for container images in the Wolfi and Alpine Linux ecosystems.

## Essential Commands

### Building and Development
```bash
# Build melange binary
make melange

# Install locally
make install

# Build a package
melange build [config.yaml]

# Build for current architecture only
melange build --arch $(uname -m) [config.yaml]

# Build with signing key
melange build --signing-key melange.rsa [config.yaml]

# Generate signing key
melange keygen
```

### Testing
```bash
# Run unit tests only
make unit

# Run integration tests (includes unit tests)
make integration

# Run end-to-end tests
make test-e2e

# Run all tests
make test

# Test a specific package
melange test [test.yaml] [package-name]
```

### Code Quality
```bash
# Format code
make fmt

# Check formatting
make checkfmt

# Run linters
make lint

# Lint melange configuration
melange lint [config.yaml]
```

### Container Images
```bash
# Build container images with ko (preferred over Docker)
make ko

# Build locally with ko
make ko-local
```

## Architecture

### Core Components
- **pkg/build/**: Build engine and pipeline execution
- **pkg/cli/**: Cobra-based CLI command implementations
- **pkg/config/**: YAML configuration parsing and validation
- **pkg/container/**: Container runtime implementations (bubblewrap, Docker)
- **pkg/pipeline/**: Pipeline step implementations
- **pkg/sbom/**: Software Bill of Materials generation
- **pkg/sign/**: APK signing functionality
- **pkg/test/**: Package testing framework

### Key Design Patterns
1. **Pipeline System**: Build steps are declarative and composable, defined in YAML
2. **Multi-Architecture**: First-class support via QEMU emulation, no cross-compilation
3. **Container Isolation**: Each build runs in an isolated container environment
4. **Reproducible Builds**: Strong emphasis on deterministic package builds
5. **Shell Overlay**: Performance optimization that caches build environments

### Pipeline Architecture
Pipelines consist of discrete steps that can:
- Fetch source code
- Run build commands
- Apply patches
- Install files
- Create subpackages
- Generate SBOMs

Common pipeline uses:
- `fetch`: Download source archives
- `git-checkout`: Clone git repositories
- `autoconf/*`: Standard autotools workflow
- `go/*`: Go-specific build steps
- `python/*`: Python package builds
- `split/*`: Create subpackages

## Development Guidelines

### Adding New Features
1. Pipeline steps go in `pkg/pipeline/`
2. CLI commands go in `pkg/cli/`
3. Tests are required - add unit tests and consider e2e tests for significant features
4. Update JSON schema if adding configuration options
5. Document new pipelines in `docs/`

### Testing Approach
- Unit tests use standard Go testing
- Integration tests use real container runtimes
- E2E tests build actual packages and verify outputs
- Test isolation ensures each test runs in a fresh environment

### Logging
Uses structured logging with slog. Context-aware logging is preferred:
```go
log := clog.FromContext(ctx)
log.Infof("building package %s", pkgName)
```

### Error Handling
- Return errors up the stack rather than logging and continuing
- Use `fmt.Errorf` with `%w` for error wrapping
- Provide context in error messages

## Important Notes

1. **Container Runtime**: Supports both bubblewrap (default) and Docker. Bubblewrap is faster but Docker is more compatible.

2. **Build Cache**: Melange caches build artifacts. Use `melange update-cache` to refresh.

3. **Multi-Stage Builds**: Subpackages allow splitting build output into multiple APKs.

4. **Configuration Validation**: Always validate melange.yaml against the JSON schema.

5. **SBOM Generation**: Automatic for all builds, outputs to `packages/` directory.

6. **Cross-Architecture**: QEMU handles emulation automatically, just specify `--arch`.

7. **Local Development**: When developing melange itself, use `make install` to test changes.

8. **Pipeline Inheritance**: Common pipeline configurations can be shared via `uses:`.

9. **Test Packages**: Built packages can be tested with `melange test` using a test configuration file.

10. **Reproducibility**: Builds are designed to be reproducible - same inputs produce identical outputs.
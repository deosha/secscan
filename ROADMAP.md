# SecScan Roadmap

## Version 1.1.0 (High Priority)
- [ ] Severity filtering (`--min-severity`, `--severity`)
- [ ] Exit codes for CI/CD (`--fail-on critical`)
- [ ] Configuration file support (`.secscan.yml`)
- [ ] Ignore/allowlist functionality
- [ ] CSV output format

## Version 1.2.0 (Performance & UX)
- [ ] Async API calls for parallel scanning
- [ ] Progress bar for large projects
- [ ] Cache management (TTL, clear, offline mode)
- [ ] Colored output with `--no-color` option
- [ ] Quiet mode (`-q`) for CI environments

## Version 1.3.0 (Integration Features)
- [ ] SARIF output for GitHub Security
- [ ] JUnit XML for CI test reports
- [ ] Markdown report generation
- [ ] Watch mode (`--watch`)
- [ ] Git diff integration (`--since`)

## Version 2.0.0 (Major Expansion)
- [ ] Ruby support (Gemfile)
- [ ] Rust support (Cargo.toml)
- [ ] Java support (Maven, Gradle)
- [ ] License compliance checking
- [ ] SBOM generation (CycloneDX, SPDX)

## Version 2.1.0 (Advanced Features)
- [ ] Dependency graph visualization
- [ ] Custom policy support
- [ ] Auto-fix with `--fix` flag
- [ ] Container/Docker scanning
- [ ] VS Code extension

## Future Considerations
- [ ] Web UI dashboard
- [ ] GitHub Action
- [ ] Remediation API
- [ ] Integration with other vulnerability databases
- [ ] Machine learning for false positive detection

## Contributing

We welcome contributions! Priority areas:
1. New language support
2. Output format plugins
3. Performance improvements
4. Documentation and examples

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
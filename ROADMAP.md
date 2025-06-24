# SecScan Roadmap

## Version 1.1.0 ✅ (Completed)
- [x] Severity filtering (`--min-severity`, `--severity`)
- [x] Exit codes for CI/CD (`--fail-on critical`)
- [x] Configuration file support (`.secscan.yml`)
- [x] Ignore/allowlist functionality
- [x] CSV output format

## Version 1.2.0 ✅ (Completed)
- [x] Colored output with `--no-color` option
- [x] Quiet mode for CI environments (`--ci`)
- [x] CVSS score filtering (`--cvss-min`)
- [x] Exploit detection (`--exploitable`)
- [x] Fix availability filter (`--has-fix`)
- [x] Statistics mode (`--stats`)

## Version 1.3.0 ✅ (Completed)
- [x] SARIF output for GitHub Security
- [x] Markdown report generation
- [x] Policy enforcement (`--policy`, `--policy-file`)
- [x] Threshold limits (`--max-critical`, `--max-high`, `--max-total`)
- [x] Strict mode (`--strict`)
- [x] Advanced configuration system

## Version 1.4.0 ✅ (Completed)
- [x] Cache management (TTL, clear, offline mode)
- [x] Multi-level cache structure (~/.secscan/cache/)
- [x] Intelligent cache invalidation
- [x] Offline mode support
- [x] Cache statistics and management
- [x] Parallel API calls with ThreadPoolExecutor
- [x] Performance optimizations (10x+ faster cached scans)

## Version 1.5.0 (In Progress - Integration Features)
- [ ] Async API calls for improved performance
- [ ] Progress bar for large projects
- [ ] Watch mode (`--watch`)
- [ ] Git diff integration (`--since`)
- [ ] JUnit XML for CI test reports
- [ ] GitHub Action official support
- [ ] GitLab CI template
- [ ] Jenkins plugin
- [ ] Auto-fix with `--fix` flag
- [ ] PR comment integration

## Version 2.0.0 (Major Expansion)
- [ ] Ruby support (Gemfile)
- [ ] Rust support (Cargo.toml)
- [ ] Java support (Maven, Gradle)
- [ ] PHP support (composer.json)
- [ ] C# support (NuGet)
- [ ] License compliance checking
- [ ] SBOM generation (CycloneDX, SPDX)

## Version 2.1.0 (Advanced Features)
- [ ] Dependency graph visualization
- [ ] Custom vulnerability database support
- [ ] Container/Docker scanning
- [ ] VS Code extension
- [ ] IntelliJ plugin
- [ ] Vulnerability trend analysis
- [ ] Team collaboration features

## Version 3.0.0 (Enterprise Features)
- [ ] Web UI dashboard
- [ ] REST API server mode
- [ ] Multi-project management
- [ ] Role-based access control
- [ ] Audit logging
- [ ] Custom reporting templates
- [ ] Integration with ticketing systems (Jira, ServiceNow)

## Future Considerations
- [ ] Machine learning for false positive detection
- [ ] Vulnerability prediction based on code patterns
- [ ] Integration with cloud security platforms
- [ ] Kubernetes admission controller
- [ ] Supply chain security features
- [ ] Real-time monitoring mode
- [ ] Mobile app dependency scanning (iOS/Android)

## Recently Completed Features 🎉

### Configuration System
- YAML/JSON configuration files
- Global and project-level configs
- Environment variable support
- CLI argument override capability
- Config validation and management commands

### Advanced Filtering
- Severity-based filtering (individual and minimum)
- CVSS score filtering
- Exploit availability detection
- Fix availability filtering
- Combined filter support

### CI/CD Integration
- Smart exit codes (0, 1, 2)
- CI-friendly output mode
- Fail-on thresholds
- Policy enforcement
- Threshold violations

### Policy System
- Inline policy strings
- JSON policy files
- Complex rule definitions
- Age-based vulnerability rules
- Fix requirement rules

### Caching System
- Multi-level cache structure (vulndb, scans, packages)
- Intelligent cache invalidation based on manifest changes
- TTL-based expiration with configurable timeouts
- Offline mode for air-gapped environments
- Cache statistics and management commands
- SHA256 integrity verification
- Parallel API calls for performance
- 10x+ performance improvement on cached scans

## Contributing

We welcome contributions! Priority areas:
1. New language support (Ruby, Rust, Java)
2. Performance improvements (async scanning)
3. Integration features (GitHub Actions, GitLab CI)
4. Progress indicators and watch mode
5. Documentation and examples

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Feedback

Have ideas for new features? Found a bug? Please open an issue on GitHub!

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.
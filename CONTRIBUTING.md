# Contributing to SecScan

Thank you for your interest in contributing to SecScan! This document provides guidelines and instructions for contributing to the project.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Priority Areas](#priority-areas)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:
- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Respect differing viewpoints and experiences

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/yourusername/secscan.git
   cd secscan
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/deosha/secscan.git
   ```

## Development Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

3. Install pre-commit hooks (optional but recommended):
   ```bash
   pip install pre-commit
   pre-commit install
   ```

## How to Contribute

### Reporting Issues

- Check if the issue already exists
- Use the issue templates when available
- Provide clear reproduction steps
- Include system information (OS, Python version)
- Add relevant logs or error messages

### Suggesting Features

- Check the [ROADMAP.md](ROADMAP.md) for planned features
- Open a discussion issue before implementing
- Explain the use case and benefits
- Consider backward compatibility

### Submitting Code

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our coding standards

3. Add or update tests as needed

4. Update documentation if applicable

5. Commit with clear messages:
   ```bash
   git commit -m "Add support for Ruby dependency scanning
   
   - Implement Gemfile parser
   - Add tests for Ruby detection
   - Update documentation"
   ```

## Pull Request Process

1. Update your fork with the latest upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

3. Create a Pull Request from your fork to the main repository

4. Ensure all checks pass:
   - Tests pass
   - Code follows style guidelines
   - Documentation is updated

5. Request review from maintainers

6. Address review feedback

7. Once approved, a maintainer will merge your PR

## Coding Standards

### Python Style

- Follow PEP 8
- Use type hints where appropriate
- Maximum line length: 100 characters
- Use meaningful variable names

### Code Structure

```python
# Good example
def parse_package_json(manifest_path: Path) -> List[Dependency]:
    """Parse JavaScript dependencies from package.json.
    
    Args:
        manifest_path: Path to package.json file
        
    Returns:
        List of Dependency objects
        
    Raises:
        JSONDecodeError: If file contains invalid JSON
    """
    with open(manifest_path, 'r') as f:
        data = json.load(f)
    
    dependencies = []
    for name, version in data.get('dependencies', {}).items():
        dependencies.append(Dependency(name, version, Language.JAVASCRIPT))
    
    return dependencies
```

### Error Handling

- Use specific exceptions
- Provide helpful error messages
- Handle edge cases gracefully
- Log warnings for non-fatal issues

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=secscan

# Run specific test file
pytest tests/test_parsers.py

# Run specific test
pytest tests/test_parsers.py::test_parse_package_json
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files as `test_*.py`
- Use descriptive test names
- Test both success and failure cases
- Mock external API calls

Example test:
```python
def test_parse_requirements_txt():
    """Test parsing requirements.txt file."""
    content = "django==3.2.0\nrequests>=2.25.0\n"
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt') as f:
        f.write(content)
        f.flush()
        
        deps = DependencyParser.parse_python(Path(f.name))
        
    assert len(deps) == 2
    assert deps[0].name == "django"
    assert deps[0].version == "3.2.0"
    assert deps[1].name == "requests"
    assert deps[1].version == "2.25.0"
```

## Documentation

### Code Documentation

- Add docstrings to all public functions and classes
- Use Google-style docstrings
- Include parameter types and return values
- Add usage examples for complex functions

### User Documentation

- Update README.md for new features
- Add examples to the demo script
- Update command-line help text
- Document configuration options

## Priority Areas

We especially welcome contributions in these areas:

### 1. New Language Support
- Ruby (Gemfile, Gemfile.lock)
- Rust (Cargo.toml, Cargo.lock)
- Java (pom.xml, build.gradle)
- PHP (composer.json, composer.lock)
- C# (packages.config, *.csproj)

### 2. Performance Improvements
- Async API calls for parallel scanning
- Caching mechanism for API responses
- Progress indicators for large scans
- Batch processing optimizations

### 3. Integration Features
- GitHub Actions workflow
- GitLab CI template
- Jenkins plugin
- VS Code extension
- Pre-commit hooks

### 4. Output Formats
- JUnit XML for test reports
- HTML reports with charts
- Excel/CSV exports
- Slack/Teams notifications

### 5. Advanced Features
- Dependency graph visualization
- Auto-fix capabilities
- License compliance checking
- SBOM generation

## Getting Help

- Join our discussions on GitHub Issues
- Check existing documentation
- Ask questions with the "question" label
- Reach out to maintainers

## Recognition

Contributors will be:
- Added to the AUTHORS file
- Mentioned in release notes
- Given credit in pull request merges

Thank you for contributing to making dependency scanning better for everyone! 🎉
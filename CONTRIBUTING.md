# Contributing to Honeypot Threat Intelligence Infrastructure

First off, thank you for considering contributing to this project! It's people like you that make this threat intelligence infrastructure better for the cybersecurity community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Contribution Workflow](#contribution-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation Standards](#documentation-standards)
- [Commit Message Guidelines](#commit-message-guidelines)

---

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## How Can I Contribute?

### Reporting Bugs

**Before submitting a bug report:**
- Check the [troubleshooting guide](docs/TROUBLESHOOTING.md)
- Search existing [GitHub issues](https://github.com/YOUR_USERNAME/honeypot-threat-intelligence/issues)
- Ensure you're using the latest version

**How to submit a good bug report:**

Create an issue with:
- Clear, descriptive title
- Detailed steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Docker version, etc.)
- Relevant logs or screenshots
- Label as `bug`

**Bug Report Template:**
```markdown
**Description:**
Brief description of the bug

**Steps to Reproduce:**
1. Step one
2. Step two
3. ...

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Environment:**
- OS: Ubuntu 22.04
- Docker: 24.0.0
- Python: 3.9.0

**Logs:**
```
Paste relevant logs here
```
```

### Suggesting Enhancements

**Enhancement suggestions are welcome for:**
- New honeypot integrations
- Additional analysis features
- Performance improvements
- Documentation improvements
- New threat intelligence formats

**How to submit an enhancement:**

Create an issue with:
- Clear title describing the enhancement
- Use case and motivation
- Proposed implementation (if applicable)
- Benefits to the project
- Label as `enhancement`

### Adding New Honeypots

To add support for a new honeypot:

1. **Configuration:** Add honeypot config in `infrastructure/t-pot/`
2. **Docker Service:** Update `infrastructure/docker-compose.yml`
3. **Logstash Parser:** Add parsing logic in `infrastructure/elk-stack/logstash.conf`
4. **Documentation:** Update README and ARCHITECTURE.md
5. **Tests:** Add validation tests
6. **Examples:** Provide sample logs

### Improving Analysis Scripts

Contributions to analysis scripts should:
- Follow existing code style
- Include error handling
- Add type hints
- Provide docstrings
- Include unit tests
- Update requirements.txt if needed

---

## Development Setup

### Prerequisites

```bash
# Required
- Docker 20.10+
- Docker Compose 1.29+
- Python 3.8+
- Git

# Recommended
- 16GB RAM
- 100GB disk space
```

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/honeypot-threat-intelligence.git
cd honeypot-threat-intelligence

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/honeypot-threat-intelligence.git
```

### Install Dependencies

```bash
# Python dependencies
pip3 install -r requirements.txt

# Development dependencies
pip3 install -r requirements-dev.txt  # If exists

# Setup environment
make setup
```

### Create Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

---

## Contribution Workflow

### 1. Make Changes

- Write clean, documented code
- Follow coding standards (see below)
- Add tests for new features
- Update documentation

### 2. Test Your Changes

```bash
# Run unit tests
make test

# Run linters
make lint

# Test deployment locally
make deploy

# Verify functionality
make diagnose
```

### 3. Commit Changes

```bash
# Stage changes
git add .

# Commit with descriptive message (see Commit Guidelines below)
git commit -m "feat: add support for new honeypot XYZ"
```

### 4. Push to Fork

```bash
git push origin feature/your-feature-name
```

### 5. Create Pull Request

- Go to GitHub and create a Pull Request
- Fill out the PR template completely
- Link related issues
- Request review from maintainers

### 6. Address Feedback

- Respond to review comments
- Make requested changes
- Push updates to same branch

---

## Coding Standards

### Python Code

**Style Guide:** Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)

**Key Points:**
```python
# Use type hints
def extract_iocs(self, days_back: int = 7) -> Dict:
    """
    Extract IOCs from logs.

    Args:
        days_back: Number of days to analyze

    Returns:
        Dictionary of extracted IOCs
    """
    pass

# Use meaningful variable names
attacker_ip = source.get('src_ip')  # Good
x = source.get('src_ip')            # Bad

# Handle errors explicitly
try:
    result = risky_operation()
except SpecificException as e:
    logger.error(f"Operation failed: {e}")
    return default_value

# Use f-strings for formatting
print(f"[+] Connected to {host}:{port}")  # Good
print("[+] Connected to %s:%d" % (host, port))  # Avoid
```

**Linting:**
```bash
# Check code quality
pylint analysis/*.py
flake8 analysis/*.py
black --check analysis/*.py

# Auto-format
black analysis/*.py
```

### Bash Scripts

**Standards:**
```bash
#!/bin/bash
# Always use shebang
set -e  # Exit on error
set -u  # Exit on undefined variable

# Use functions
function_name() {
    local var="value"  # Use local variables
    echo "$var"        # Quote variables
}

# Validate inputs
if [ -z "$1" ]; then
    echo "Error: Missing argument"
    exit 1
fi

# Check command existence
if ! command -v docker &> /dev/null; then
    echo "Docker not found"
    exit 1
fi
```

### YAML/JSON

- Use 2-space indentation
- Validate syntax before committing
- Include comments for complex sections
- Use consistent quoting

### Documentation

- Use Markdown for all docs
- Include table of contents for long docs
- Use code blocks with language hints
- Include examples
- Keep line length ≤ 80 characters where reasonable

---

## Testing Guidelines

### Unit Tests

**Location:** `tests/`

**Naming:**
```
test_<module>_<function>.py
```

**Structure:**
```python
import unittest

class TestIOCExtraction(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        pass

    def test_valid_ip_extraction(self):
        """Test IP extraction with valid data"""
        result = extract_ip("192.168.1.1")
        self.assertTrue(result)

    def tearDown(self):
        """Clean up after tests"""
        pass
```

**Running Tests:**
```bash
# All tests
make test

# Specific test
python3 -m pytest tests/test_ioc_extraction.py

# With coverage
make test-coverage
```

### Integration Tests

Test full workflows:
```bash
# Deploy infrastructure
make deploy

# Generate test attack
ssh root@localhost -p 2222

# Verify logging
curl "localhost:9200/honeypot-*/_count"

# Run analysis
make report

# Verify outputs exist
ls reports/generated/
```

---

## Documentation Standards

### Code Documentation

**Python Docstrings:**
```python
def function_name(param1: str, param2: int) -> bool:
    """
    Brief description of function.

    Longer description with implementation details if needed.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        True if successful, False otherwise

    Raises:
        ValueError: If param1 is empty
        ConnectionError: If cannot connect to service

    Example:
        >>> function_name("test", 42)
        True
    """
```

**Inline Comments:**
```python
# Good: Explain WHY, not WHAT
# Calculate threat score based on frequency and diversity
score = (frequency * 0.5) + (diversity * 0.3)

# Bad: Obvious comment
# Set x to 5
x = 5
```

### Markdown Documentation

**File Structure:**
```markdown
# Title

Brief description

## Table of Contents
- [Section 1](#section-1)
- [Section 2](#section-2)

---

## Section 1

Content here...

### Subsection 1.1

More content...

## Section 2

Content here...
```

**Code Blocks:**
```markdown
```bash
# Always specify language
docker-compose up -d
```
```

---

## Commit Message Guidelines

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat:** New feature
- **fix:** Bug fix
- **docs:** Documentation changes
- **style:** Code formatting (no logic change)
- **refactor:** Code restructuring
- **perf:** Performance improvement
- **test:** Adding/updating tests
- **chore:** Maintenance tasks
- **ci:** CI/CD changes

### Examples

**Good:**
```
feat(analysis): add malware family classification

Implemented automated malware family detection using signature
matching. Supports Mirai, XMRig, and common botnet families.

- Added pattern matching for 15+ families
- Integrated with IOC extraction pipeline
- Updated documentation

Closes #42
```

**Good (simple):**
```
fix: resolve Elasticsearch connection timeout

Added retry logic with exponential backoff to handle
intermittent ES connection issues.
```

**Bad:**
```
fixed stuff
```

**Bad:**
```
Updated files
```

### Scope Examples

- `analysis` - Analysis scripts
- `infra` - Infrastructure/Docker
- `docs` - Documentation
- `scripts` - Automation scripts
- `config` - Configuration files

---

## Pull Request Process

### Before Submitting

- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if applicable)
- [ ] Commits are clean and descriptive
- [ ] No merge conflicts
- [ ] PR description is complete

### PR Template

Use the provided template:
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
```

### Review Process

1. **Automated Checks:** CI/CD must pass
2. **Code Review:** At least one maintainer approval
3. **Testing:** Reviewer tests functionality
4. **Merge:** Maintainer merges when ready

---

## Release Process

*(For maintainers)*

1. Update CHANGELOG.md
2. Bump version in relevant files
3. Create release branch: `release/v1.x.x`
4. Tag release: `git tag -a v1.x.x -m "Release v1.x.x"`
5. Push tag: `git push origin v1.x.x`
6. Create GitHub release
7. Merge to main

---

## Recognition

Contributors will be recognized in:
- GitHub Contributors page
- CHANGELOG.md (significant contributions)
- README.md acknowledgments (major features)

---

## Questions?

- **General Questions:** Open a [Discussion](https://github.com/YOUR_USERNAME/honeypot-threat-intelligence/discussions)
- **Bug Reports:** Open an [Issue](https://github.com/YOUR_USERNAME/honeypot-threat-intelligence/issues)
- **Security Issues:** See [SECURITY.md](SECURITY.md)

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to making threat intelligence more accessible!** 🛡️

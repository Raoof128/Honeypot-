# Pull Request

## Description

<!-- Provide a brief description of the changes in this PR -->

## Type of Change

<!-- Check all that apply -->

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Code refactoring
- [ ] Performance improvement
- [ ] Configuration change

## Related Issues

<!-- Link related issues. Use "Closes #123" to auto-close issues when PR is merged -->

- Closes #
- Related to #

## Changes Made

<!-- List the key changes in this PR -->

- Change 1
- Change 2
- Change 3

## Testing Performed

<!-- Describe the tests you ran to verify your changes -->

**Test Environment:**
- OS: [e.g., Ubuntu 22.04]
- Docker: [e.g., 24.0.0]
- Python: [e.g., 3.9.0]

**Test Steps:**
1. Step 1
2. Step 2
3. Step 3

**Test Results:**
```
Paste test output here
```

## Screenshots

<!-- If applicable, add screenshots to demonstrate the changes -->

**Before:**
<!-- Screenshot of behavior before changes -->

**After:**
<!-- Screenshot of behavior after changes -->

## Checklist

<!-- Check all that apply. Reviewers will verify these items -->

### Code Quality
- [ ] Code follows project style guidelines
- [ ] Code has been linted (`make lint`)
- [ ] No hardcoded secrets or credentials
- [ ] Error handling implemented
- [ ] Logging added where appropriate
- [ ] Comments added for complex logic

### Testing
- [ ] Unit tests added/updated
- [ ] All tests pass (`make test`)
- [ ] Integration tests performed
- [ ] Tested in clean environment
- [ ] No breaking changes (or documented below)

### Documentation
- [ ] README.md updated (if needed)
- [ ] CHANGELOG.md updated
- [ ] Code comments added
- [ ] Docstrings updated
- [ ] docs/ files updated (if applicable)

### Infrastructure
- [ ] docker-compose.yml validated
- [ ] Configuration files updated
- [ ] Dependencies added to requirements.txt
- [ ] No unnecessary dependencies added

### Security
- [ ] No security vulnerabilities introduced
- [ ] Input validation implemented
- [ ] Authentication/authorization considered
- [ ] Data privacy maintained
- [ ] Secrets properly managed

## Breaking Changes

<!-- If this PR introduces breaking changes, list them here -->

- N/A

or

- Breaking change 1: Description and migration path
- Breaking change 2: Description and migration path

## Migration Guide

<!-- If users need to take action to upgrade, provide steps here -->

```bash
# Example migration steps
make backup
make stop
git pull
make deploy
```

## Deployment Notes

<!-- Any special considerations for deployment -->

- Requires new environment variable: `NEW_VAR=value`
- Requires database migration
- Requires service restart
- Other notes

## Performance Impact

<!-- Describe any performance implications -->

- [ ] No performance impact
- [ ] Performance improved
- [ ] Performance impact (describe below)

**Details:**
<!-- If performance is impacted, describe the impact and justification -->

## Additional Notes

<!-- Any additional information reviewers should know -->

## Reviewer Checklist

<!-- For reviewers to verify -->

- [ ] Code reviewed
- [ ] Tests reviewed and pass
- [ ] Documentation adequate
- [ ] No security concerns
- [ ] Performance acceptable
- [ ] Ready to merge

---

**By submitting this pull request, I confirm that my contribution is made under the terms of the MIT License.**

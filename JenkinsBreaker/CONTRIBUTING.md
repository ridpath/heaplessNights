# Contributing to JenkinsBreaker

## Contribution Workflow

### 1. Fork the Repository

Click the Fork button and clone your fork locally:

```bash
git clone https://github.com/your-username/heaplessNights.git
```

### 2. Create a Feature Branch

Keep `main` clean; always branch for new features or fixes:

```bash
git checkout -b feature/your-feature-name
```

### 3. Code Standards

- Use clear, descriptive variable names
- Add docstrings to functions and classes
- Update README documentation for new functionality
- Follow PEP8 for Python code
- Use `rich` for CLI output when applicable
- Keep UI components and logic decoupled
- Comment code for educational value

### 4. Test Your Code

- Verify existing functionality remains intact
- Test new features before committing
- Include example usage in documentation

### 5. Commit and Push

```bash
git add .
git commit -m "Add: [Brief Description of Feature or Fix]"
git push origin feature/your-feature-name
```

### 6. Submit a Pull Request

1. Navigate to your fork on GitHub
2. Click Compare & Pull Request
3. Provide clear title and description
4. Tag appropriately (bug, feature, enhancement)

## Exploit Module Guidelines

When adding new exploit modules:

- Document in README with CVE reference
- Log key outputs clearly
- Include affected version information
- Provide example usage
- Test against vulnerable lab environment

## Questions

For questions about contribution process, open an issue with the `question` label.

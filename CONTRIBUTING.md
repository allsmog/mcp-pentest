# Contributing to MCP Penetration Testing Framework

Thank you for your interest in contributing to the Model Context Provider (MCP) for Penetration Testing! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please help us keep this project open and inclusive. By participating, you agree to respect all people who contribute through reporting issues, posting feature requests, updating documentation, submitting pull requests, and other activities.

## How Can I Contribute?

### Reporting Bugs

If you find a bug, please create an issue with the following information:
- A clear and descriptive title
- Steps to reproduce the issue
- Expected vs. actual behavior
- Screenshots (if applicable)
- Environment details (OS, browser, version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues:
- Use a clear and descriptive title
- Provide a detailed description of the suggested enhancement
- Explain why this enhancement would be useful
- Include any relevant examples or mock-ups

### Tool Integrations

We especially welcome contributions that add new tool integrations. To contribute a new tool:
1. Check existing integrations for reference
2. Follow the plugin architecture pattern
3. Include comprehensive tests
4. Document the tool's functionality and parameters

### Pull Requests

1. Fork the repository
2. Create a branch from `main`
3. Make your changes
4. Run tests to ensure your code works correctly
5. Submit a pull request

Please include a clear description of the changes and reference any related issues.

## Development Setup

### Prerequisites

- Python 3.8+
- Docker and Docker Compose (for running the full stack)
- Git

### Installation Steps

1. Clone your fork of the repository
2. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```
3. Set up pre-commit hooks:
   ```bash
   pre-commit install
   ```

### Running Tests

```bash
pytest tests/
```

## Coding Guidelines

### Python Style Guide

- Follow PEP 8 style guidelines
- Use type hints for function parameters and return values
- Document functions, classes, and modules using docstrings
- Keep lines to a maximum of 100 characters

### Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests after the first line

### Documentation

- Update documentation for any changed or new functionality
- Use clear and consistent terminology
- Include examples where appropriate

## Review Process

All submissions require review. We strive to review pull requests within one week.

## Security Considerations

Given the nature of this tool, please be especially mindful of security issues:

- Never commit credentials, API keys, or sensitive information
- Follow security best practices in code (input validation, proper error handling, etc.)
- Report potential security vulnerabilities privately via email rather than public issues

Thank you for contributing to the MCP Penetration Testing Framework!

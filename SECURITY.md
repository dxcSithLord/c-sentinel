# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | ✅ Yes             |
| < 0.3   | ❌ No              |

## Reporting a Vulnerability

If you discover a security vulnerability in C-Sentinel, please report it responsibly.

### How to Report

**Email**: william@fstopify.com

**Please include**:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Resolution timeline**: Depends on severity, typically within 30 days

### What We Ask

- **Don't** disclose publicly until we've had a chance to fix it
- **Don't** exploit the vulnerability beyond what's needed to demonstrate it
- **Do** provide enough detail for us to reproduce and fix the issue

### Scope

Security issues we're interested in:

- Buffer overflows or memory corruption
- Command injection vulnerabilities
- Path traversal issues
- Information disclosure in sanitization
- Policy engine bypasses

### Out of Scope

- Issues requiring physical access to the machine
- Social engineering attacks
- Denial of service (C-Sentinel is a diagnostic tool, not a service)

## Security Design

C-Sentinel is designed with security in mind:

- **Read-only by design**: Never modifies system state
- **No network listeners**: Doesn't open any ports
- **Sanitization layer**: Strips sensitive data before external transmission
- **Policy engine**: Validates AI suggestions before display
- **No root required**: Runs with minimal privileges

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities (unless you prefer to remain anonymous).

---

Thank you for helping keep C-Sentinel secure! 🛡️

# Contributing to C-Sentinel

First off, thank you for considering contributing to C-Sentinel! It's people like you that make open source work.

## Ways to Contribute

### 🐛 Reporting Bugs

Found a bug? Please open an issue with:

- A clear, descriptive title
- Steps to reproduce the problem
- Expected vs actual behaviour
- Your environment (OS, kernel version, compiler)
- Any relevant output or error messages

### 💡 Suggesting Features

Have an idea? Open an issue and tell us:

- What problem it solves
- How you envision it working
- Whether you'd be interested in implementing it

### 🔧 Submitting Code

1. **Fork the repository** and create your branch from `main`
2. **Write clear, readable code** that follows the existing style
3. **Test your changes** - make sure `make` succeeds with no warnings
4. **Update documentation** if you're changing behaviour
5. **Submit a pull request** with a clear description of changes

## Code Style

C-Sentinel follows strict C99 with these conventions:

```c
/* Comments use C-style block comments */
/* NOT // C++ style */

/* Functions are snake_case */
int capture_fingerprint(fingerprint_t *fp);

/* Types end with _t */
typedef struct { ... } fingerprint_t;

/* Constants are UPPER_SNAKE_CASE */
#define MAX_PROCESSES 1024

/* Braces on same line for control structures */
if (condition) {
    do_something();
}
```

### Compiler Flags

All code must compile cleanly with:
```bash
gcc -Wall -Wextra -Werror -pedantic -std=c99
```

No warnings allowed. This is non-negotiable.

### Memory Safety

- Always use `snprintf()`, never `sprintf()`
- Check all return values
- Define `MAX_*` limits for all arrays
- No dynamic allocation where static will do

## Areas Where Help is Wanted

We'd particularly welcome contributions in:

| Area | Description |
|------|-------------|
| **Platform support** | BSD, macOS, Solaris ports |
| **Application probes** | nginx, postgres, redis, docker |
| **Sanitization patterns** | New PII/secret detection patterns |
| **Documentation** | Examples, tutorials, translations |
| **Testing** | Edge cases, failure modes, fuzzing |

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/c-sentinel.git
cd c-sentinel

# Build
make

# Run tests
make test

# Run with debug symbols
make DEBUG=1
./bin/sentinel --quick
```

## Commit Messages

Write clear, concise commit messages:

```
feat: Add PostgreSQL probe support

- Parse pg_stat_activity for connection info
- Detect long-running queries (>30s)
- Add to network probe output
```

Format: `type: Short description`

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

## Pull Request Process

1. Update the README.md if you've added features
2. Update DESIGN_DECISIONS.md if you've made architectural choices
3. Ensure all tests pass and code compiles cleanly
4. Your PR will be reviewed by a maintainer

## Questions?

Not sure about something? Open an issue and ask! There are no stupid questions.

---

Thank you for helping make C-Sentinel better! 🛡️

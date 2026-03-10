# Contributing to ioguard

Thank you for your interest in contributing to ringwall. This document explains
the process for contributing changes and the standards we follow.

## Getting Started

1. Fork the repository and clone it locally
2. Start the development container:
   ```bash
   cd deploy/podman
   make dev
   ```
3. Make your changes on a feature branch
4. Submit a pull request

## Development Workflow

### Build and Test

All builds run inside the Podman development container (OL10-based).

```bash
cmake --preset clang-debug              # Configure
cmake --build --preset clang-debug      # Build
ctest --preset clang-debug              # Run tests
```

### Static Analysis

```bash
cmake --build --preset clang-debug --target codechecker    # CodeChecker (clang-sa + clang-tidy)
cmake --build --preset clang-debug --target pvs-studio     # PVS-Studio
cmake --build --preset clang-debug --target analyze        # Both
```

### Code Formatting

```bash
cmake --build --preset clang-debug --target format         # clang-format
cmake --build --preset clang-debug --target format-check   # Check only
```

## Code Standards

### C23 Conventions

- **Language**: C23 (`-std=c23`), Linux only (kernel 6.7+, glibc 2.39+)
- **Naming**: `rw_module_verb_noun()` functions, `rw_module_name_t` types, `RW_MODULE_VALUE` enums
- **Errors**: Return negative errno (`-ENOMEM`, `-EINVAL`), use `goto cleanup`
- **Allocation**: Always `sizeof(*ptr)`, never `sizeof(type)`
- **Security**: `[[nodiscard]]` on all public API, `explicit_bzero()` for secrets
- **Column limit**: 100 characters
- **Include guards**: `RINGWALL_MODULE_FILE_H`

See `.claude/skills/coding-standards/SKILL.md` for the full reference.

### Testing

- All new code must have unit tests (Unity framework)
- Test files: `tests/unit/test_<module>.c`
- Sanitizers: ASan+UBSan on every commit, MSan with Clang
- Fuzzing: LibFuzzer targets in `tests/fuzz/` (Clang only)

### Security

- Never use banned functions: `strcpy`, `sprintf`, `gets`, `strcat`, `atoi`, `system()`
- Constant-time comparison for secrets (`ConstantCompare` from wolfCrypt)
- Use `<stdckdint.h>` for size/length arithmetic
- Run static analyzers before submitting

## Pull Request Process

1. Open an issue first to discuss significant changes
2. Create a feature branch from `master`
3. Make focused, reviewable commits with descriptive messages
4. Ensure all checks pass: build, tests, formatting
5. Update documentation if your change affects user-facing behavior

### PR Checklist

- [ ] Tests added or updated
- [ ] Build and tests pass (`cmake --build && ctest`)
- [ ] `format-check` passes
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated (if user-facing change)
- [ ] Commit messages follow conventional commits (`feat:`, `fix:`, `refactor:`)

## Reporting Issues

- **Bugs**: Use the GitHub Issues bug report template
- **Features**: Use the GitHub Issues feature request template
- **Security**: See [SECURITY.md](SECURITY.md) for responsible disclosure

## License

By contributing to ioguard, you agree that your contributions will be licensed
under the [GNU General Public License v3.0](LICENSE).

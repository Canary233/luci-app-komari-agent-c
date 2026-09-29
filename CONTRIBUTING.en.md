# Contributing Guide

[中文](CONTRIBUTING.md) | **English**

Thank you for considering a contribution to Komari Agent (C language version)! This document describes the process and conventions for contributing.

## General Requirements

- Ensure local build and unit tests pass before submitting (see "Build and Test" below)
- All code comments must be in English
- Use clear variable names; handle platform compatibility for cross-platform code
- All memory allocations and file operations must check return values
- Do not reference issue numbers, PR numbers, or abstract problem codes in code comments; comments should explain "why", not "what"

## Git Commit Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <subject>

- <change entry 1>
- <change entry 2>
  <continuation line for long entries>
```

> **Commit message language**: `type` and `scope` must be in English; `subject` and `body` are written in Chinese (technical terms and identifiers stay in English). The subject summarizes 2-4 key points joined by `、`; the body uses a `- ` bullet list where each entry states what was done and why; do not reference issue numbers. See [AGENTS.md](AGENTS.md) for the full conventions.

### Commit types (type)

`feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`

### Scopes (scope)

`i18n`, `luci`, `openwrt`, `workflows`, `core`, `utils`, `deps`, `tests`, `ci`, `config`

### Examples

Chinese commit message example:

```
fix(core): 修复 WebSocket 重连时未清理 fragment buffer 的问题

- 在 ws_client_disconnect 中重置 fragment_len 与 fragment_capacity
- 修复后 v2 协议长连接断开重连不再出现解析失败
```

Multi-area fix example (subject summarizes the key points, body maps each change):

```
fix(openwrt): 修复系统用户创建、procd 环境注入与令牌暴露

- postinst 改用 busybox 兼容方式创建 komari 系统用户，原版 OpenWrt 不提供 groupadd/useradd
- 代理环境变量合并为单次 procd_set_param env 注入，分次调用仅最后一对生效
```

## Code Style

- **Language standard**: C99
- **Comment language**: English, using Doxygen style (`@param`, `@return`)
- **Memory safety**: All `malloc`/`calloc`/`strdup` allocations must check return values; set pointers to NULL after free to avoid double-free
- **File operations**: All `fopen`/`fread`/`fwrite` calls must check return values
- **Cross-platform**: Linux-specific APIs (e.g., `/proc`, `forkpty`) must be guarded by platform detection macros
- **Hardening flags**: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-Wformat -Werror=format-security`, `-fvisibility=hidden`, PIE enabled by default

## Build and Test

### Local Build

```bash
# Configure and build (default Release + tests)
cmake --preset default
cmake --build build

# Debug mode
cmake --preset debug
cmake --build build
```

### Run Unit Tests

```bash
cmake --preset default
cmake --build build
ctest --test-dir build --output-on-failure
```

### Run Tests in Docker

Run tests without installing a local toolchain:

```bash
./scripts/docker-build.sh test
```

### Cross-Architecture Compilation

Docker-based cross-compilation for 8 CPU architectures:

```bash
./scripts/docker-build.sh amd64    # Single architecture
./scripts/docker-build.sh all      # All architectures
```

See [docker/README.md](docker/README.md) for details.

### CMake Presets

The project provides 9 standardized presets (see `CMakePresets.json`):

| Preset | Purpose |
|--------|---------|
| `default` | Default Release + tests |
| `debug` | Debug + verbose diagnostics |
| `release` | Release + LTO, no tests |
| `relwithdebinfo` | Optimized + debug symbols |
| `minsizerel` | Minimum size (embedded targets) |
| `sanitize` | ASan + UBSan |
| `coverage` | Code coverage |
| `openwrt` | OpenWrt cross-compile (requires SDK env) |
| `analyze` | clang-tidy static analysis |

## Testing Conventions

- Use the [Unity](https://github.com/ThrowTheSwitch/Unity) v2.6.1 framework for unit tests
- Test files go in the `tests/` directory, named `test_<module>.c`
- `KOMARI_BUILD_TESTS` and `BUILD_TESTING` CMake options are kept in sync (see `komari-agent-c/cmake/BuildOptions.cmake`)
- Attach corresponding unit tests when adding features or fixing bugs
- Ensure `ctest --test-dir build --output-on-failure` passes before submitting

## PR Process

1. Fork the repository and create a feature branch: `git checkout -b feat/your-feature`
2. Write code and commit messages following the conventions above
3. Ensure local build and unit tests pass
4. Submit a PR with a title following Conventional Commits format (e.g., `fix(core): 修复 xxx` or `fix(core): fix xxx`)
5. Describe the motivation, scope of impact, and test results in the PR description
6. Wait for CI checks (8-arch Docker binary build, 10-arch OpenWrt package build, LuCI package build, code quality checks)

## Project Structure

```
luci-app-komari-agent-c/
├── luci-app-komari-agent-c/ # LuCI frontend (Lua + CBI)
├── komari-agent-c/          # OpenWrt backend package + C source code
│   ├── cmake/               # Modular CMake configuration (5 modules)
│   ├── include/             # Public headers (version.h, etc.)
│   ├── src/                 # C source code (organized by module)
│   ├── tests/               # Unity unit tests
│   ├── files/               # OpenWrt init/config files
│   ├── Makefile             # OpenWrt package definition
│   ├── CMakeLists.txt       # Top-level CMake configuration
│   └── CMakePresets.json    # 9 standardized build presets
├── docker/                  # Docker cross-compile environment
├── scripts/                 # Build/package/verify scripts
├── .github/workflows/       # CI/CD configuration (ci.yml + release.yml)
└── AGENTS.md                # Project maintenance guide (internal)
```

## Contact

- Submit Issues: [GitHub Issues](https://github.com/zhz8888/luci-app-komari-agent-c/issues)
- Submit PRs: [GitHub Pull Requests](https://github.com/zhz8888/luci-app-komari-agent-c/pulls)

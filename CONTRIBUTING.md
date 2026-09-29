# 贡献指南

**中文** | [English](CONTRIBUTING.en.md)

感谢您考虑为 Komari Agent（C 语言版本）贡献代码！本文档说明参与贡献的流程与规范。

## 通用要求

- 提交前确保本地构建与单元测试通过（见下文「构建与测试」一节）
- 所有代码注释必须使用英文
- 变量命名清晰明了，跨平台代码需处理平台兼容性
- 所有内存分配与文件操作必须检查返回值
- 不在代码注释中引用 issue 编号、PR 编号或抽象的问题代号，注释解释「为什么」而非「做了什么」

## Git 提交规范

采用 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

```
<type>(<scope>): <subject>

- <变更条目 1>
- <变更条目 2>
  <长条目续行>
```

> **提交信息语言**：`type` 与 `scope` 必须使用英文；`subject` 与 `body` 使用中文（技术名词、标识符保留英文）。标题以顿号/并列结构概括 2-4 个要点；正文使用 `- ` 逐条变更列表，每条说明「做了什么 + 为什么」；不引用问题编号。完整规范见 [AGENTS.md](AGENTS.md)。

### 提交类型（type）

`feat`、`fix`、`docs`、`style`、`refactor`、`perf`、`test`、`build`、`ci`、`chore`、`revert`

### 作用范围（scope）

`i18n`、`luci`、`openwrt`、`workflows`、`core`、`utils`、`deps`、`tests`、`ci`、`config`

### 示例

中文提交信息示例：

```
fix(core): 修复 WebSocket 重连时未清理 fragment buffer 的问题

- 在 ws_client_disconnect 中重置 fragment_len 与 fragment_capacity
- 修复后 v2 协议长连接断开重连不再出现解析失败
```

跨模块多点修复示例（标题概括要点、正文逐条对照）：

```
fix(openwrt): 修复系统用户创建、procd 环境注入与令牌暴露

- postinst 改用 busybox 兼容方式创建 komari 系统用户，原版 OpenWrt 不提供 groupadd/useradd
- 代理环境变量合并为单次 procd_set_param env 注入，分次调用仅最后一对生效
```

## 代码规范

- **语言标准**：C99
- **注释语言**：英文，使用 Doxygen 风格（`@param`、`@return`）
- **内存安全**：所有 `malloc`/`calloc`/`strdup` 等分配必须检查返回值；释放后置空指针避免 double-free
- **文件操作**：所有 `fopen`/`fread`/`fwrite` 等调用必须检查返回值
- **跨平台**：Linux 特有 API（如 `/proc`、`forkpty`）需通过平台检测宏隔离
- **硬化标志**：默认启用 `-fstack-protector-strong`、`-D_FORTIFY_SOURCE=2`、`-Wformat -Werror=format-security`、`-fvisibility=hidden`、PIE

## 构建与测试

以下命令在 `komari-agent-c/` 目录中执行（C 源码与 CMake 工程位于该目录）。

### 本地构建

```bash
# 配置并构建（默认 Release + 测试）
cmake --preset default
cmake --build build

# 调试模式
cmake --preset debug
cmake --build build
```

### 运行单元测试

```bash
cmake --preset default
cmake --build build
ctest --test-dir build --output-on-failure
```

### CMake 预设

项目提供 9 个标准化预设（见 `CMakePresets.json`）：

| 预设 | 用途 |
|------|------|
| `default` | 默认 Release + 测试 |
| `debug` | Debug + 详细诊断 |
| `release` | Release + LTO，无测试 |
| `relwithdebinfo` | 优化 + 调试符号 |
| `minsizerel` | 最小体积（嵌入式目标） |
| `sanitize` | ASan + UBSan |
| `coverage` | 代码覆盖率 |
| `openwrt` | OpenWrt 交叉编译（需 SDK 环境） |
| `analyze` | clang-tidy 静态分析 |

## 测试规范

- 使用 [Unity](https://github.com/ThrowTheSwitch/Unity) v2.6.1 框架编写单元测试
- 测试文件放置在 `tests/` 目录下，命名格式 `test_<module>.c`
- `KOMARI_BUILD_TESTS` 与 `BUILD_TESTING` 两个 CMake 选项同步（见 `komari-agent-c/cmake/BuildOptions.cmake`）
- 新增功能或修复 bug 时，应附上对应单元测试
- 提交前确保 `ctest --test-dir build --output-on-failure` 全部通过

## PR 流程

1. Fork 仓库并创建特性分支：`git checkout -b feat/your-feature`
2. 按上述规范编写代码与提交信息
3. 本地通过构建与单元测试
4. 提交 PR，标题遵循 Conventional Commits 格式（如 `fix(core): 修复 xxx`）
5. 在 PR 描述中说明改动动机、影响范围与测试情况
6. 等待 CI 检查（包含 10 架构 OpenWrt 包构建、LuCI 包构建、代码质量检查、单元测试）

## 项目结构

```
luci-app-komari-agent-c/
├── luci-app-komari-agent-c/ # LuCI 前端（Lua + CBI）
├── komari-agent-c/          # OpenWrt 后端包 + C 源代码
│   ├── cmake/               # CMake 模块化配置（5 个模块）
│   ├── include/             # 公共头文件（version.h 等）
│   ├── src/                 # C 源代码（按模块组织）
│   ├── tests/               # Unity 单元测试
│   ├── files/               # OpenWrt init/config 文件
│   ├── Makefile             # OpenWrt 包定义
│   ├── CMakeLists.txt       # 顶层 CMake 配置
│   └── CMakePresets.json    # 9 个标准化构建预设
├── .github/workflows/       # CI/CD 配置（ci.yml + release.yml）
└── AGENTS.md                # 项目维护指南（内部文档）
```

## 联系方式

- 提交 Issue：[GitHub Issues](https://github.com/zhz8888/luci-app-komari-agent-c/issues)
- 提交 PR：[GitHub Pull Requests](https://github.com/zhz8888/luci-app-komari-agent-c/pulls)

# AE-Locker

**简体中文** | [English](README.en.md)

`AE-Locker` 是一个用 C++20 编写的命令行文件加密工具，使用 **AES-256-CTR** 对文件内容做多线程并行加密，使用 **AES-256-GCM** 对原始文件名加密（使其在加密后不可见），并以 **HMAC-SHA256** 对整个文件做完整性认证。密钥通过 **scrypt** KDF 从用户口令派生。支持可选的 **LZ4 / zstd** 压缩-后-加密(compress-then-encrypt):通过 `--compress` / `-z` / `--fast` 在加密前对每个 chunk 独立压缩,解密时自动识别压缩算法并还原。

构建工具链：**Clang + LLD + ThinLTO + Ninja + CMake**。

## 目录

- [特性](#特性)
- [构建](#构建)
- [快速开始](#快速开始)
- [本地化 (Locale / Language)](#本地化-locale-language)
- [批量目录加密/解密（\`--auto\`)](#批量目录加密-解密-auto)
- [三种 CLI 调用方式](#三种-cli-调用方式)
- [TUI 交互界面](#tui-交互界面)
- [三种口令来源](#三种口令来源)
- [完整选项列表](#完整选项列表)
- [加密文件格式（\`.ae-locked\`)](#加密文件格式ae-locked)
- [加密设计](#加密设计)
- [流式 I/O 与内存模型](#流式-i-o-与内存模型)
- [项目结构](#项目结构)
- [安全说明](#安全说明)
- [跨架构产物 (\`dist/arch/\`)](#跨架构产物-dist-arch-)
- [限制](#限制)
- [许可证](#许可证)

## 特性

- **可选压缩**:加密前对每个 chunk 独立做 LZ4 或 zstd 压缩;压缩与加密均在 worker 线程中并行执行;解密时根据 header 自动选择解压算法(v1 文件保持原样可读)
- **AES-256-CTR** 批量加密，可并行化（每 chunk 独立 IV）
- **AES-256-GCM** 仅用于文件名加密（小数据带认证）
- **scrypt** KDF 从口令派生 64 字节密钥材料：32 字节 `file_key` + 32 字节 `hmac_key`
- **HMAC-SHA256** 覆盖 `header || ciphertext` 作为尾部认证脚
- **文件名不可见**：原始文件名在 header 中只以密文形式存在；解密时从 header 还原
- **多线程**：单文件内 `N` 个 compress worker 并行（`-j N` 控制；encrypt 步骤因 v2 IV 需累积 CT size 为单线程串行），多文件之间也并行
- **进度条**：每文件独立 + Overall 总进度（手写 ASCII `[=====>]` 渲染器，无第三方依赖，支持原地刷新）
- **多种 CLI 风格**：子命令、`-c flag`、`--cli` 交互式
- **多种口令来源**：交互式（默认）、文件（`-p`，需 `--no-safe`）、环境变量（`--password-env-var`，需 `--no-safe`）
- **输出不覆盖**：若 `foo.txt.ae-locked` 已存在，加密会拒绝执行并报错
- **安全护栏**：从文件/环境变量读口令默认拒绝执行，需显式 `--no-safe` 确认

## 构建

### 通用依赖

- **Clang 15+**（C++20.coroutine / `std::span`）
- **LLD**（链接器，ThinLTO 后端）
- **Ninja**
- **CMake 3.25+**（preset 用 `CMAKE_CXX_COMPILER_TARGET` 等 3.25+ 才稳的工具链功能）
- **OpenSSL 3.x**（提供 `EVP_KDF_scrypt`、`EVP_MAC`）
- **（可选）GNU readline + libtinfo** — 提供 `--cli` REPL 的历史与 Tab 补全；探测不到时 CMake 自动降级为 `std::getline` 模式（无历史、无补全），其它功能不受影响
- **LZ4 v1.9.4 / zstd v1.5.7 / ftxui v5.0.0** 均由 CMake
  `FetchContent` 自动拉取并静态构建，无需系统预装；首次 `cmake` 配置会从
  GitHub clone，之后增量复用 `build/_deps/`

`CMakePresets.json` 自带三个 preset：

| preset | 目标架构 | 链接方式 | 用途 |
|---|---|---|---|
| `default`         | host (x86_64 / aarch64) | 动态           | 主开发路径，产物在 `build/ae-locker` |
| `debug`           | host                    | 动态，无 ThinLTO | 调试 |
| `aarch64-static`  | aarch64 Linux           | **全静态** (`-static-pie`，无 `NEEDED`) | x86_64 主机交叉编译，产物在 `build-aarch64/ae-locker` |

所有 preset 共享：

- `-flto=thin` + `-Wl,--thinlto-cache-dir=<build>/.lto-cache`（`debug` 关）
- `-fuse-ld=lld` + `--ld-path=$(which ld.lld)`
- `-Wall -Wextra -Wpedantic -Werror -Wconversion -Wimplicit-int-conversion -Wshadow`

> 三个 preset **互不冲突**：`default` / `debug` 产出在 `build/`，`aarch64-static`
> 产出在 `build-aarch64/`，cache 完全隔离，可以在同一棵源码树里来回切。

### Debian / Ubuntu — x86_64 主机（最常见）

```bash
sudo apt-get install -y clang lld ninja-build cmake libssl-dev libreadline-dev
git clone <repo-url> && cd AE-Locker
cmake --preset default       # 一次性配置（首跑会 FetchContent 拉取 lz4/zstd/ftxui）
cmake --build build          # 增量编译
./build/ae-locker --version
```

`libreadline-dev` 可省略 — CMake 探测不到 readline 会自动降级到 `std::getline`
的 REPL 模式（无历史、无 Tab 补全），其它功能不受影响。

### Debian / Ubuntu — aarch64 native 主机（Raspberry Pi OS 64-bit 等）

在 aarch64 主机上 `cmake --preset default` 直接可用 —— clang 在 aarch64 host
上的默认 target 就是 `aarch64-linux-gnu`，preset 完全兼容。安装、编译命令与
x86_64 主机路径完全相同：

```bash
sudo apt-get install -y clang lld ninja-build cmake libssl-dev libreadline-dev
cmake --preset default
cmake --build build
./build/ae-locker --version
```

产物为动态链接 binary，依赖同机 `libssl.so.3` / `libstdc++.so.6` / `libreadline.so.8`
等；把 `ae-locker` 拷到同发行版同代 glibc 的 aarch64 机器上跑需要先 `apt install`
对应运行时库（或者改用下述交叉编译的静态产物）。

### Debian / Ubuntu — 在 x86_64 主机交叉编译 aarch64 **静态** binary

需启用 Debian multiarch arm64 并预装交叉工具链与 arm64 静态库。一次性 setup：

```bash
# 1) 启用 arm64 multiarch
sudo dpkg --add-architecture arm64
sudo apt-get update

# 2) host 工具：clang / lld / ninja / cmake
sudo apt-get install -y clang lld ninja-build cmake

# 3) arm64 binutils（ar/ranlib/strip 必须按 arch 区分格式;LLD 虽能 link arm64,但归档仍用 arch-specific ar）
sudo apt-get install -y binutils-aarch64-linux-gnu

# 4) 交叉 glibc + libgcc/libstdc++ 静态库
sudo apt-get install -y libc6-dev-arm64-cross g++-aarch64-linux-gnu

# 5) arm64 静态 OpenSSL + readline + tinfo（multiarch 包，:arm64 后缀）
sudo apt-get install -y libssl-dev:arm64 libreadline-dev:arm64 libtinfo-dev:arm64
```

之后在 `AE-Locker/` 源码树里：

```bash
cmake --preset aarch64-static          # 一次性配置
cmake --build --preset aarch64-static  # 增量编译
# 产物在 build-aarch64/ae-locker，无任何 NEEDED 项，可 scp 到任意标准 aarch64
# Linux（glibc 2.31+）直接跑，无需目标机安装任何 runtime lib
```

`cmake/aarch64-linux-gnu.cmake` toolchain file 已强制把 OpenSSL / readline /
tinfo / libstdc++ / libgcc / glibc 全部 link 成 `.a`，并用 `-static-pie`
产生一个无 `NEEDED` 的 ET_DYN binary。产物支持范围详见下文「跨架构产物」。

### macOS

macOS 默认使用 Apple `ld64`，不是 LLD；OpenSSL / readline 走 Homebrew。把
Homebrew 的 llvm（带 lld）与 openssl/readline 路径显式暴露给 CMake：

```bash
brew install cmake ninja llvm@18 openssl@3 readline

# Intel mac 把 /opt/homebrew 换成 /usr/local
export PATH=/opt/homebrew/opt/llvm/bin:$PATH
export OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
export Readline_ROOT=/opt/homebrew/opt/readline

cmake --preset default
cmake --build build
./build/ae-locker --version
```

> macOS 路径**尚未实测**。 ThinLTO + LLD 与 macOS 的 code signing / notarization
> 偶有冲突。若遇 LLD 链接问题，可 `-DENABLE_THINLTO=OFF` 关 ThinLTO，并把
> `CMAKE_LINKER_TYPE` 设为 `ld64`（或让 CMake 自动 fallback 到 Apple linker）。

### Termux on Android — on-device 编译

Termux 是 AE-Locker 在 Android 上跑的**唯一可行路径**：直接在 Termux 里用 Termux 自带的
clang 编译。Termux clang 的默认 target 是 `aarch64-linux-android`（Bionic libc），
产物本身就是 Bionic-native，可在 Termux 直接跑。`dist/arch/aarch64/ae-locker` 静态
产物（glibc）**不可**用于 Termux，详见下文「不支持的平台 — Termux / Android」。

```bash
# 在 Termux (任意 64-bit Android 设备) 内：
pkg install clang lld ninja cmake openssl readline

# CMakePresets.json 的 preset 假定 Debian multiarch layout，
# Termux 的 prefix 在 $PREFIX (默认 /data/data/com.termux/files/usr)，
# 与 preset 假定不同 —— 因此 preset 不能直接用，需手动传 cache var:
cmake -B build -G Ninja \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_THINLTO=ON \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

cmake --build build
./build/ae-locker --version
```

> Termux on-device 编译路径**尚未实测**。已知风险点：
> 1. FetchContent 第一次会从 GitHub `git clone` lz4 / zstd / ftxui，受
>    Termux 网络代理或磁盘权限限制时，可能需要改用 `URL` 源或预先 vendor 源码
> 2. Termux 的 libtinfo 不一定独立存在（readline 与 ncurses 在 Termux 上常被合并），
>    若 `find_library(Readline_TINFO_LIBRARY NAMES tinfo ncurses)` 找不到
>    `libtinfo`，CMake 仍会链 readline 但 REPL 在某些终端下亮色/光标控制会异常
> 3. Termux 的 `mmap` / `getrandom` 行为与 Linux glibc 不完全一致 ——
>    `RAND_bytes` 与流式 I/O 在 Android 6.0+ 应正常，但低版本 Android
>    可能 `/dev/urandom` 不可用
>
> 实测通过后欢迎反馈，会更新本节。

## 快速开始

```bash
# 加密（交互式输入口令）
./build/ae-locker encrypt secret.txt
# → secret.txt.ae-locked

# 解密（口令同上）
./build/ae-locker decrypt secret.txt.ae-locked -o ./out/
# → ./out/secret.txt  （文件名从 header 还原）

# 查看加密文件元数据（不解密）
./build/ae-locker list secret.txt.ae-locked
```

多文件并行加密：

```bash
./build/ae-locker encrypt a.txt b.txt c.txt -j 8
```

## 本地化 (Locale / Language)

`AE-Locker` 内置中英双语支持。语言按以下优先级自动检测，可用 `--lang` 强制覆盖；全程无第三方 i18n 库依赖。

| 优先级 | 来源                              | 备注                                                  |
|:------:|:----------------------------------|:-----------------------------------------------------|
|   1    | `--lang zh\|en`（命令行任意位置） | 显式最高优先级；后出现的值会覆盖前者                   |
|   2    | `$LC_ALL`                         | 形如 `zh_CN.UTF-8` → zh；不含 `zh` 字串 → en          |
|   3    | `$LC_MESSAGES`                    | 同上                                                 |
|   4    | `$LANG`                           | 同上                                                 |
| (默认) | 均未设置                          | 英语 (en)                                             |

`-v` / `--verbose` 会向 stderr 打印一行探测信息：

```
[lang] detected=zh effective=zh (env: LANG=zh_CN.UTF-8)
```

颜色输出（错误前缀、进度条填充、密码提示等）遵守 `NO_COLOR` / `CLICOLOR=0` / 终端 tty 检测，亦可用 `--no-color` 全量关闭（也包括进度条 ANSI 光标控制与画面重绘）。`--no-color` 模式下进度条退化为每文件一次的纯文本 stderr 行，便于管道捕获或脚本集成。

`-q` / `--quiet` 仅抑制进度条，错误仍照常输出。

### 用法示例

```bash
# 中文本地化（CLI 提示、帮助、进度、错误信息）
./build/ae-locker --lang zh encrypt secret.txt

# 仅影响本次运行的环境变量路由
LC_ALL=zh_CN.UTF-8 ./build/ae-locker encrypt secret.txt

# 显示语言探测行
./build/ae-locker encrypt secret.txt -v

# 关掉彩色与光标 ANSI
./build/ae-locker --no-color encrypt secret.txt -o ./out/

# 管道模式：自动检测 stdin 是否为 tty，非 tty 时不关回显
printf 'pw\npw\n' | ./build/ae-locker encrypt secret.txt
```

### 退出代码表

`cli_main` 仍只暴露 `int` 返回值（公开签名不变），但内部按场景分别返回以下退出码：

| 退出码 | 含义                                                           | 触发场景                                                                          |
|:-----:|:---------------------------------------------------------------|:--------------------------------------------------------------------------------|
|   0   | 成功 (Ok)                                                       | 加密/解密/list 正常完成                                                           |
|   2   | 参数错误 (Arg)                                                  | 未知命令 / 缺少 flag 值 / 不支持的 flag 值（`--lang fr` / `--compress bogus` 等）/ 密码不匹配、空密码 / 无可加密文件 / 无输入文件 / `--max-depth` 未与 `--auto` 一起用 / `--auto` 给的目录不存在 |
|   3   | I/O 错误 / 输入文件已存在 (Io)                                  | 目标 `.ae-locked` 文件已存在（不覆盖护栏）/ 目录创建失败 / 文件不可读                |
|   4   | 密钥派生 / 认证失败 (Auth)                                      | 解密时密码错（HMAC 校验失败 / 文件被篡改 / salt 不匹配）                          |
|   5   | 内部不可恢复错误 (Internal)                                      | 异常落到 `cli_main` 顶层兜底分支                                                 |

`ae-locker list` 子命令即使对"不是 `.ae-locked` 文件"的入参也返回 0（仅打印提示），不影响脚本以退出码聚合判断其他子命令的成功/失败。

## 批量目录加密/解密（`--auto`)

`--auto <dir>` 进入批量模式：递归扫描指定目录中的所有常规文件,镜像源目录的子目录结构落到 `-o/--output-dir` 下,避免不同子目录中同名文件冲突。

```bash
# 递归加密 ./secrets 下所有文件到 ./encrypted,镜像源目录结构
./build/ae-locker encrypt --auto ./secrets --max-depth 3 -o ./encrypted

# 递归解密:扫描 ./encrypted/*.ae-locked 用 header 中还原的文件名输出到 ./decrypted,
# 子目录结构镜像到 ./decrypted下
./build/ae-locker decrypt --auto ./encrypted -o ./decrypted
```

约定：

- `--auto <dir>`:递归扫描该目录。`-o/--output-dir` **必须**显式给出,作为镜像源子目录结构的输出根。
- `--max-depth <N>`:递归深度控制。`-1` = 不限(默认);`0` = 仅 `--auto` 给的目录内的直系文件;`1` = 当前层 + 一层子目录;依此类推。
- encrypt:跳过 `.ae-locked` 结尾的文件(防止二次加密自己的产物);只对常规文件处理。
- decrypt:只处理 `.ae-locked` 结尾的常规文件,从 header 还原原始文件名作为输出文件名。
- 跳过 symlink(防止 cycle 攻击);跳过非常规文件(socket/device/fifo)。
- 输出现在用 `[源相对路径].ae-locked` (encrypt)  / `[源相对子目录]/[header 还原文体名]` (decrypt) 落地 `-o`,与单文件模式同样遵循"存在即拒"(不覆盖已有产物)。
- `--auto` 与位置文件参数互斥,二者只能给其一;`--max-depth` 单独给出(没有 `--auto`)会报错。
- 空(无可加密/解密的文件)目录会以"no eligible files found"报错(非静默成功)。

## 三种 CLI 调用方式

| 方式 | 命令 |
|---|---|
| **子命令（默认）** | `ae-locker encrypt <file> [options]` |
| **flag 形式** | `ae-locker -c encrypt <file> [options]` |
| **交互式** | `ae-locker --cli`（进入 REPL，支持 `encrypt` / `decrypt` / `list` / `quit`，以及帮助内部命令 `help` / `?` / `h`） |

### 子命令级 `--help` / `-h`

`ae-locker --help` 输出总览；任意子命令后追加 `--help`（或 `-h`）只打印该子命令的简介、相关选项与示例，并立即以退出码 0 返回（不真正执行 encrypt/decrypt/list，即便其它参数已存在）：

```bash
ae-locker encrypt --help    # encrypt 频专属帮助(EN)
ae-locker decrypt --help    # decrypt 频专属帮助
ae-locker list --help       # list 频专属帮助
ae-locker encrypt -h        # 与 --help 完全一致
ae-locker --lang zh encrypt --help   # 中文版 encrypt 专属帮助
ae-locker encrypt foo.txt --help -o out -z   # --help 短路,不加密,退出 0
```

`ae-locker help encrypt` **不**存在 —— 顶层的 `help` 仍是 unknown command（退出 2），仅在 `--cli` REPL 内部可用。

### `--cli` REPL 内部帮助命令

进入 `ae-locker --cli` 后，REPL 接受额外的帮助命令（仅 REPL 内部，并不暴露为可执行子命令）：

| 命令 | 行为 |
|---|---|
| `help` / `?` / `h` | 打印与 `ae-locker --help` 相同的总体帮助到 STDOUT |
| `help encrypt` / `? encrypt` / `h decrypt` / `? list` 等 | 打印对应子命令的专属帮助到 STDOUT |
| `help bogus`（或任何非 encrypt/decrypt/list 的主题） | 向 STDERR 输出本地化「未知帮助主题」错误，REPL **不**退出，仍重新提示 |

REPL 启动时会把简短提示打到 STDERR 一次，提示用户可输入 `help` / `?` / `h` 与 `quit`。`quit` / `exit` / `q` 仍以 ExitCode::Ok 结束 REPL。

### `--cli` REPL readline 支持

`ae-locker --cli` 在编译期探测 GNU readline + libtinfo 作为可选链接依赖；若两者可用，REPL 即由 readline 驱动，提供：

- **行编辑**：←/→/Home/End 词内移动，Ctrl-A / Ctrl-E，Backspace/Delete 编辑光标位置。
- **历史记录**：↑/↓ 翻阅当前进程内的输入历史（非空行才入历史；空行/纯空白不入历史）。
- **Tab 补全**：根据光标所在位置感知 CLI 拓扑，补全候选如表所示：

| 输入位置 | 补全内容 |
|---|---|
| 行首 / `encrypt` 子命令前 | `encrypt` / `decrypt` / `list` / `help` / `?` / `h` / `quit` / `exit` / `q` |
| `help` / `?` / `h` 后的位置参数 | `encrypt` / `decrypt` / `list` |
| 任意子命令后以 `--` 开头的 token | 该子命令可识别的长 flag（例如 `encrypt` 多 `--compress` / `--fast` / `--level` / `--chunk-size` / `--auto` / `--max-depth`；`decrypt` 仅多 `--auto` / `--max-depth`；`list` 仅通用 `--help` / `--lang` / `--no-color` / `--verbose` / `--quiet` / `--no-safe` / `--password-file` / `--password-env-var` / `--jobs` / `--output-dir`） |
| 任意子命令后单 `-` 开头的 token | 上述长 flag + 通用短 flag（`-p` / `-j` / `-o` / `-h` / `-v` / `-q` / `-z` / `-pev`，只列短 flag）|
| `--compress ` 之后的 token | `none` / `lz4` / `zstd` |
| `--lang ` 之后的 token | `en` / `zh` |
| 其它任何位置 | readline 默认的文件名补全（fallback） |

补全命令以 `--xxx=value` 形式时 strip 到 `--xxx` 再做前缀过滤。唯一匹配时 readline 自动补齐并补一个空格（`rl_completion_append_character = ' '`）；多候选时第一次 `Tab` 响铃提示歧义，第二次 `Tab` 列出全部候选，行为与 bash 一致。`--no-safe` 之类的 flag 不因为补全被改写。

#### 编译期依赖探测

`CMakeLists.txt` 用 `find_library(Readline_LIBRARY NAMES readline)` + `find_path(Readline_INCLUDE_DIR NAMES readline/readline.h)` 探测；二者皆命中即设置 `AE_LOCKER_HAVE_READLINE=ON`（cache 变量），并把：

- `-DAE_LOCKER_HAVE_READLINE=1` 暴露给所有 AE-Locker TU；
- `${Readline_LIBRARY}`（以及找到时的 `${Readline_TINFO_LIBRARY}`，避免 -Wl,--as-needed 在 ThinLTO 下解掉传递依赖）加入 `target_link_libraries(ae-locker PRIVATE ...)`。

readline 不是 REQUIRED，任何一项缺失都会降级：`AE_LOCKER_HAVE_READLINE=OFF`、build 链入 `0`、`cli.cpp` 的 `#if AE_LOCKER_HAVE_READLINE` 走 `std::getline` 路径，REPL 启动时向 STDERR 打一行 `[repl] readline not found at build time — using line mode (no history, no Tab completion)`（本地化：中文构建环境显示对应中文）。CREPL 完全无 readline.h 依赖——`include/ae-locker/repl.hpp` 头文件不代理 `readline.h`，仅暴露两个 entry point：`repl_readline(prompt, out)` 与 `repl_install_completer()`；`src/repl.cpp` 在内部 `extern "C" { #include <readline/readline.h> #include <readline/history.h> }`。

构建后 `ldd build/ae-locker | grep readline` 在已探测到 libreadline 的环境下可看到 `libreadline.so.8` 与 `libtinfo.so.6`。

### Shell tab 自动补全

`ae-locker --completion <shell>` 在运行时按 CLI 已知的 flag 集生成可直接 `eval` / source 的 shell 补全脚本，写入 stdout 并以退出码 0 退出。支持 bash、zsh、fish 三种 shell；脚本是 `ae-locker` 二进制自身在内存中通过纯 C++ 拼装字符串生成的，不调用任何外部子进程、不发起网络请求，也不依赖任何第三方补全库。脚本文本固定为英文（不随 `--lang` 变化），因为脚本是给 shell 解析的，而不是给终端用户逐行阅读的。

启用方式：

```bash
# bash —— 在 ~/.bashrc 里加一句：
eval "$(ae-locker --completion bash)"

# zsh：先确保已开启补全（一般 .zshrc 里已有 autoload -Uz compinit && compinit）
eval "$(ae-locker --completion zsh)"
# 或者把脚本拷到 fpath 任意目录里命名为 _ae-locker（命令名 + 下划线前缀）：
#   ae-locker --completion zsh > ~/.zsh/_ae-locker
#   fpath=(~/.zsh $fpath); autoload -Uz compinit && compinit

# fish：可直接 source
ae-locker --completion fish | source
```

补全内容覆盖：

- 子命令名 `encrypt` / `decrypt` / `list` 在 `ae-locker ` 后自动补全。
- 各子命令的短/长 flag（如 `ae-locker encrypt -<TAB>`、`ae-locker decrypt --<TAB>`）。
- `--compress <TAB>` 补全 `none` / `lz4` / `zstd`；`--lang <TAB>` 补全 `en` / `zh`。
- `-p` / `--password-file` 补文件；`-o` / `--output-dir` / `--auto` 补目录；位置参数走 shell 默认的文件补全。
- `list` 子命令后面**不会**补出 `--compress` / `-z` / `--fast` / `--level` / `--auto` / `--max-depth` 这些仅 encrypt 用的 flag。

`--completion` 也可以等号形式给出：`ae-locker --completion=bash` 与空格形式行为完全一致。`--lang` / `--no-color` 若出现在 `--completion` 之前会被识别（错误信息按所选语言本地化），但脚本正文不受影响。未识别的 shell 名会以非零退出码 2 返回并打到 STDERR 一条本地化错误信息，stdout 不会有任何半截脚本流出：

```bash
$ ae-locker --completion bogus; echo "rc=$?"
error: unsupported shell 'bogus' (choose: bash, zsh, fish)
rc=2
$ ae-locker --completion; echo "rc=$?"
error: missing shell argument (use: bash|zsh|fish)
rc=2
```

如果使用 `make install`（CMake 的 `install` 目标），构建系统会调用刚装好的 `ae-locker` binary 把三种脚本分别生成到 `${CMAKE_INSTALL_DATADIR}` 下的标准 vendor 路径：

| Shell | 安装路径                                                     |
|---|---|
| bash  | `${datadir}/bash-completion/completions/ae-locker`               |
| zsh   | `${datadir}/zsh/site-functions/_ae-locker`                       |
| fish  | `${datadir}/fish/vendor_completions.d/ae-locker.fish`            |

这样无需 `eval` 也能让对应 shell 自行加载。源码树不保留任何生成产物，安装的脚本永远反映当前 binary 实际识别的 flag 拓扑。

## TUI 交互界面

`ae-locker --tui` 启动基于 ftxui 的全屏终端交互界面，提供菜单式加密/解密操作流程。

```bash
ae-locker --tui                # 启动 TUI（中文或英文取决于语言探测）
ae-locker --lang zh --tui      # 强制中文本地化 TUI
ae-locker --lang en --tui      # 强制英文 TUI
```

### TUI 守卫条件

TUI 在进入菜单前先做两项检查；任一不通过则退出码 2 并打印错误到 STDERR：

| 条件 | 检查 | 失败信息（中文） |
|---|---|---|
| stdin + stderr 必须是 tty | `isatty(STDIN_FILENO) && isatty(STDERR_FILENO)` | `TUI 模式需要交互式终端 (tty)` |
| 彩色支持必须启用 | `color_enabled()`（即无 `--no-color` / `NO_COLOR` / `CLICOLOR=0`） | `TUI 模式需要彩色支持 (不要使用 --no-color 或 NO_COLOR)` |

非 tty 下运行（管道/重定向/CI）会自动触发第一项拒绝；`--no-color` 无论放在 `--tui` 之前还是之后都会在第二项被拦截。

### 与其它顶层 flag 的互斥

`--tui` 与 `--cli`、`--help`、`--version`、`<子命令>`（`encrypt` / `decrypt` / `list`）是「parallel top-level flags」—— 首个出现在 argv 中的那个胜出，后续的并行 flag 被忽略。`--lang` 可与 `--tui` 共存（影响 TUI 文字语言）。`--completion` 在更早阶段已被处理，不会与 `--tui` 冲突。

### 主菜单 4 项

| 中文 | 英文 | 操作 |
|---|---|---|
| 加密 (Encrypt) | Encrypt | ↑/↓ 选中后 Enter 进入加密向导 (4 步) |
| 解密 (Decrypt) | Decrypt | ↑/↓ 选中后 Enter 进入解密向导 (3 步) |
| 查看 (List) | List | ↑/↓ 选中后 Enter 进入 List 文件选择器 |
| 退出 (Quit) | Quit | 退出 TUI, 退出码 0 |

默认高亮在第一项 (加密)。Esc 或选中「退出」会终止整个 TUI 会话；其余三项执行完对应 wizard / picker 后都会**循环回到主菜单**(用户可继续下一次操作),只有 Quit 真正关闭 TUI。

### Wizard 多步流程

Wave D 之后的 TUI 把每个加密/解密操作拆成多步向导(不再是一屏所有字段),并在顶部用 `[1/4] [2/4] [3/4] [4/4]` 进度药丸(pill bar)展示当前进度:

```
        加密 —— 填写字段后选择 完成
        [1/4]  [2/4]  [3/4]  [4/4]
        ──────────────────────────────
              步骤 1/4: 选择文件
        ──────────────────────────────
        [交互区域]
        ──────────────────────────────
          ← 上一步  下一步 →  完成  取消
```

每步的「下一步」按钮会先跑该步的字段校验,失败时在交互区下方显示红色错误文案并停留在当前步,只有通过校验才会前进一步。最后一步 (密码) 时「下一步」会变成「完成」按钮的字面写入策略是「始终显示 4 个按钮,Next 按钮在最后一步被禁用并切灰,用户改按 Finish 触发实际加密/解密」。Esc 或「取消」按钮在任何步骤都直接退出 wizard **回到主菜单** (而非整个 TUI 会话)。

完成后,wizard 返回主菜单(用户可继续下一次操作); Quit/Esc 仍是唯一真正关闭 TUI 的入口。

### 文件浏览器 (file browser)

step 0 / List picker 复用同一个文件浏览器组件。每行格式为:

| 前缀 | 含义 |
|---|---|
| `[ ]` | 未选中 |
| `[*]` | 文件被选中 (用户对它按过 Space) |
| `[-]` | 目录 — 至少有一个子孙文件被选中 (内部部分选中) |

目录前缀永远显示 `[ ]` 或 `[-]`,目录本身不能被「选中」(只能进入)。目录列表排序: `..` 始终在最顶 (除根目录),其余先目录后文件,字母升序。

| 按键 | 作用 |
|---|---|
| ↑ / ↓ | 在文件列表中移动光标 |
| Enter | 光标在目录上时进入该目录; 光标在 `..` 上时回到上级 |
| Space | 光标在文件上时切换选中/未选中 |
| Tab / Tab+Shift | 在交互区与底部按钮行之间切换焦点 (step 0 专有拦截,见下文) |

「不安全」(symlink、特殊文件、socket 等)被自动跳过;`only_dot_ae_locked` 为 true 时列表只显示 `.ae-locked` 结尾的常规文件,方便解密向导 / List picker 缩小候选集。

### Tab 焦点拦截 (step 0)

step 0 的交互区(file browser)在顶部 step_stack 容器内,底部 buttons row 是另一个兄弟组件。Wave D 在 wizard 的 CatchEvent 层手动拦截 `Event::Tab`/`Event::TabReverse`:

- 当前焦点在 step_stack 内、current step = 0 时按 Tab → 焦点移植到 buttons row (让用户能用 Tab+Tab 到达「下一步」,而不需要先穿过文件浏览器里所有条目)
- 当前焦点在 buttons row 时按 Tab+Shift → 焦点回到 step_stack

其他 step (1/2/3) 的交互区都是常规 Input/Button 组合,Tab 行为走 ftxui 默认容器导航。

### Encrypt wizard — 4 步

| 步 | 标题 | 字段 |
|---|---|---|
| 1/4 | 选择文件 | 文件浏览器 (Space 选,Enter 进入目录,`..` 返回上级) |
| 2/4 | 压缩参数 | 不压缩 / `lz4 (快)` / `zstd (均衡)` 三个 Button(互斥 Radio); 压缩级别 Input (zstd 1..22,其他算法时禁用并 dim)|
| 3/4 | 输出与并发 | 输出目录 Input (空 = 与输入同目录); 并发数 Input (0 = 自动推荐) |
| 4/4 | 密码 | 密码 Input (hidden); 确认密码 Input (hidden) |

每步校验规则:

| 步 | 校验 |
|---|---|
| 1 | 至少选了一个文件 (`bs.selected` 不为空) |
| 2 | 无(zstd 时 level 通过 `validate_encrypt_step_compress` 检查 1..22) |
| 3 | 无 |
| 4 | 密码非空; 与确认密码一致 |

全部通过后,按「完成」按钮 wizard 返回主菜单的同时整个 TUI 退出 alt-screen,`run_encrypt` 在普通终端中执行(`cout` / `cerr` / 进度条直通用户),执行完毕打印结果行,提示「按回车返回主菜单」,等待用户输入后回到主菜单。

### Decrypt wizard — 3 步

| 步 | 标题 | 字段 |
|---|---|---|
| 1/3 | 选择 .ae-locked 文件 | 文件浏览器 (只列出 `.ae-locked` 常规文件) |
| 2/3 | 输出与并发 | 输出目录 Input; 并发数 Input (0 = 自动推荐) |
| 3/3 | 密码 | 密码 Input (hidden) (解密无确认密码字段) |

校验:

| 步 | 校验 |
|---|---|
| 1 | 至少选了一个 `.ae-locked` 文件 |
| 2 | 无 |
| 3 | 密码非空 |

完成后流程与 Encrypt 相同:退出 alt-screen → `run_decrypt` 执行 → 打印结果 → 回车 → 主菜单。

### List picker

「查看」不再是占位卡片:它打开一个独立文件浏览器(只列出 `.ae-locked` 文件),底部「查看」按钮执行 `run_list` 打印元数据; 「取消」按钮返回主菜单。Esc 在 picker 内同样返回主菜单。

### 密码处理

ftxui 的 `Input` 组件在设置 `password=true` 后隐藏字符显示,不回显到终端行。用户在 wizard 第 4 步 (Encrypt) 或第 3 步 (Decrypt) 填写密码后,「完成」触发 `execute_encrypt` / `execute_decrypt`:用 `mkstemp` 创建临时文件写入明文密码,然后以 `PasswordMode::FromFile` + `--no-safe` 模式调用 `run_encrypt` / `run_decrypt`。加密/解密完成后立即将临时文件填充零字节并 `unlink`,防止磁盘残留。

### 键盘操作 (主菜单 / wizard / picker 通用)

| 按键 | 主菜单 | wizard 交互区 | wizard button row | List picker |
|---|---|---|---|---|
| ↑ / ↓ | 在菜单项间移动 | 在 file browser 列表里移动 | (no-op) | 在 file browser 列表里移动 |
| Enter | 选中进入对应 wizard / picker | 进入目录 / 触发 on_enter | 触发当前按钮 | 进入目录 |
| Space | (no-op) | 切换文件选中 | (no-op) | 切换文件选中 |
| Tab | (no-op) | 切换到 buttons row (step 0) / 组件内导航(其他 step) | Tab+Shift 切回 step_stack (step 0);Tab 切到下一按钮 | (no-op) |
| Esc | 退出 TUI (rc=0) | 退出 wizard 回主菜单 | 退出 wizard 回主菜单 | 退出 picker 回主菜单 |

### 跨平台与依赖

ftxui 通过 CMake FetchContent 自动拉取,与 lz4、zstd 一致。首次 `cmake --preset default` 会从 GitHub 下载 ftxui 源码并编译为静态库,与 `ae-locker` 静态链接。`ae-locker --tui` 仅在拥有 POSIX termios 的平台上可用 (Linux / macOS)。

## 三种口令来源

| 模式 | 用法 | 安全护栏 |
|---|---|---|
| 交互式（默认） | `ae-locker encrypt foo.txt` 后提示输入 | 无（安全） |
| 文件 | `ae-locker encrypt -p ./pw.txt --no-safe foo.txt` | **必须** `--no-safe` |
| 环境变量 | `LOCK_PASSWORD=xxx ae-locker encrypt --password-env-var --no-safe foo.txt` | **必须** `--no-safe` |

`--password-env-var` 可缩写为 `-pev`。

不加 `--no-safe` 时从文件/环境变量读口令会被拒绝并报错，避免 fsync 日志、core dump、进程列表泄漏口令的风险。

## 完整选项列表

```
Commands:
  encrypt    加密一个或多个文件为 .ae-locked 容器
  decrypt    解密一个或多个 .ae-locked 容器
  list       打印 .ae-locked 容器的元数据（不解密）

Options:
  -p, --password-file <path>   从文件读口令（需 --no-safe）
      --password-env-var       从 $LOCK_PASSWORD 读口令（需 --no-safe）
      --no-safe                确认使用不安全的口令来源
  -j, --jobs <N>               每文件 worker 线程数（默认 hardware_concurrency）
  -o, --output-dir <dir>       输出目录（默认与输入同目录）
      --chunk-size <bytes>     加密分块大小（默认 1 MiB；需 ≥4096 且为 16 倍数）
  -z                            Shorthand for --compress zstd (balanced compression)
      --compress <algo>          Compress before encrypt: none|lz4|zstd (default: none)
      --fast                     Shorthand for --compress lz4 (fast, low ratio)
      --level <N>                Compression level: zstd 1..22 (default 3); lz4 ignores
  -v, --verbose                额外状态打到 stderr
  -q, --quiet                  关闭进度条（错误仍输出）
      --lang <en|zh>           覆盖语言探测；可在子命令前/后任意位置出现
      --no-color               关闭彩色与进度条 ANSI 光标控制（NO_COLOR / CLICOLOR=0 亦生效）
      --version                打印版本
  -h, --help                   打印帮助
```

## 加密文件格式（`.ae-locked`）

```
+────────────────+──────────────────────────────────────+
│ Fixed Header   │ v1: 112 bytes; v2: 124 bytes          |
+────────────────+──────────────────────────────────────+
│ Encrypted      │ filename_len bytes                   │
│ Filename       │                                      │
+────────────────+──────────────────────────────────────+
│ Tag Length      │ 4 bytes (be32 = 16)                 │
+────────────────+──────────────────────────────────────+
│ Filename Tag   │ 16 bytes (AES-256-GCM tag)           │
+────────────────+──────────────────────────────────────+
│ Ciphertext     │ v1: original_size bytes              │
│ Region         │ v2: sum of per-chunk compressed CT   │
+────────────────+──────────────────────────────────────+
│ Offset Table   │ v2 only: chunk_count × 4 bytes (be32)│
+────────────────+──────────────────────────────────────+
│ HMAC Footer    │ 32 bytes (HMAC-SHA256)              │
+────────────────+──────────────────────────────────────+
```

### Fixed Header（124 字节，big-endian）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0   | 16 | `magic`        | `ENCF0001v1\0\0\0\0\0\0` |
| 16  | 4  | `version`      | `1` |
| 20  | 4  | `algorithm_id` | `0x02` = `AES_256_CTR_HMAC_SHA256` |
| 24  | 4  | `kdf_id`       | `0x02` = `SCRYPT` |
| 28  | 4  | `kdf_N`        | `16384` (N=2^14) |
| 32  | 4  | `kdf_r`        | `8` |
| 36  | 4  | `kdf_p`        | `1` |
| 40  | 32 | `salt`         | 随机盐 |
| 72  | 16 | `base_iv`      | 随机 IV 基 |
| 88  | 4  | `flags`        | `0x01` = filename present |
| 92  | 4  | `filename_len` | 加密后文件名字节数 |
| 96  | 8  | `original_size`| 原文件字节数 |
| 104 | 4  | `chunk_size`   | 分块大小（默认 1 MiB） |
| 108 | 4  | `chunk_count`  | chunk 总数 |
| 112 | 4  | `compression_id` | v2 字段;`0` = NONE / `1` = LZ4 / `2` = ZSTD(v1 文件读出的值为 NONE) |
| 116 | 8  | `stored_size`  | v2 字段;密文区 + offset table 的总字节数(v1 文件读出 = `original_size`) |

> v1 文件没有 offset 112 / 116 这两个字节,v2 新增。读入时由 HeaderReader 自动归一化:将 v1 视为 `compression_id=NONE`、`stored_size=original_size`,从而解密路径对 v1/v2 一致。写路径永远输出 v2。

## 加密设计

### 密钥派生

```
scrypt(password, salt, N=16384, r=8, p=1, maxmem=64 MiB) → 64 bytes
  ├─ bytes [0..31]  → file_key  (AES-256 key)
  └─ bytes [32..63] → hmac_key  (HMAC-SHA256 key)
```

每文件使用独立的随机 `salt`（32 字节）和 `base_iv`（16 字节），均由 `RAND_bytes` 生成。

### 文件名加密（AES-256-GCM）

- **Key**：`file_key`
- **Nonce**：`SHA-256(file_key)[0..11]`（12 字节，确定性，安全因每文件 file_key 不同）
- **AAD**：`SHA-256(magic || version_be32 || algorithm_id_be32 || salt || base_iv || original_size_be64)`
- **明文**：原始文件名字节序列
- **Tag**：16 字节 GCM tag，存于 header

AAD 把 header 的固定字段绑进来，使篡改 header 后解密会 GCM 验证失败。

### 内容加密（AES-256-CTR）

每 chunk 的 IV 从 `base_iv` 派生（gocryptfs 模式）：

```
chunk_iv = base_iv
chunk_iv[8..15] (低 64 位) = big-endian( base_counter + block_offset )

# 其中 block_offset = (chunk_index × chunk_size) / AES_BLOCK_SIZE
```

高 64 位是 per-file 的随机 nonce，保证同口令同文件不同次加密也 IV 不同；低 64 位是块计数器，保证同文件内不同 chunk 不重用 IV。

CTR 模式是对称的，加密和解密用同一函数；体内多线程把所有 chunk 切到固定线程池，每个线程拥有独立的 `EVP_CIPHER_CTX`（OpenSSL 上下文非线程安全）。

### 内容压缩（LZ4 / zstd）

每个 chunk 先用 LZ4 或 zstd 压缩，再用 AES-256-CTR 加密；压缩与加密均在 worker 线程中并行执行。

v2 文件 layout：每个 chunk 的 compressed CT 是变长的，文件尾部有一个 offset table 记录每个 chunk 的 compressed 大小（be32 × chunk_count）。HMAC 覆盖 `header_serialised || chunk CT || offset_table`；v1 没有 offset table，HMAC 仅覆盖 `header_serialised || ct`。解密端读取时根据 version 判断是否将 offset table 纳入 HMAC。

IV 派生改为 `derive_chunk_iv_v2`：高 64 位 = base_iv[0..7] XOR be64(chunk_index)；低 64 位 = base_counter + (累积 CT 字节数 / 16)。既保证每 chunk 独立 IV，又对变长 chunk 仍单调递增。v1 派生公式 `derive_chunk_iv(base_iv, i * chunk_size / AES_BLOCK_SIZE)` 适用于等长 chunk。

安全论证：压缩-后-加密对静态文件加密是安全的（参考 7z / ZFS / OpenPGP）；CRIME/BREACH 类攻击需要交互式 chosen-plaintext oracle，文件静态加密不构成该场景。残余信息泄漏只剩"压缩比本身泄露文件类型/熵"，对正常用户低风险。

即使 `--compress none`（或未指定），v2 仍会写 offset table（单解密路径）；v1 文件可读但不再写。

### 完整性认证（HMAC-SHA256）

```
mac = HMAC-SHA256(hmac_key, header_serialised || chunk CT || offset_table)
```

32 字节 HMAC 写在文件尾部。v2 的 HMAC 覆盖 `header_serialised || chunk CT || offset_table`；v1 没有 offset table，HMAC 仅覆盖 `header_serialised || ct`。解密时按相同顺序重算并做常数时间比较（`CRYPTO_memcmp`），v1/v2 由 version 字段自动区分，任何 header/ciphertext/offset table 篡改会被检测到。

## 流式 I/O 与内存模型

v2 使用流式 chunk pipeline 代替旧的"整体读入内存"模型，内存峰值与文件大小解耦。

### 加密流

```
reader (单线程顺序读) → N× compress worker (并行, -j) → encrypt-then-write (单线程, 串行)
                                                                       ↓
                                                              ofstream + streaming HMAC
                                                                       ↓
                                                          写 offset_table → HMAC → 32B footer
```

- reader 单线程顺序从源文件读取 chunk
- N 个 compress worker（由 `-j` 控制）并行执行 LZ4/zstd 压缩
- 单线程加密 + 写出串行执行：因为 v2 的 `derive_chunk_iv_v2` 需要累积前序 chunk 的 CT size 才能计算当前 IV
- 写 ofstream 的同时 streaming `HMAC.update(ct_chunk)`
- 全部 chunk 处理完后顺序写 offset_table，update HMAC 包含 offset_table，最后写 32 字节 footer

### 解密流

```
reader (header + offset_table) → N× decrypt+decompress (并行, -j) → 单线程顺序写 .lockdec.tmp
                                                                               ↓
                                                                      streaming HMAC
                                                                               ↓
                                                              EOF → 比 footer → rename / unlink
```

- reader 读 header 和 offset_table，获取每 chunk 的密文偏移
- N 个 worker（由 `-j` 控制）并行做 CTR decrypt + decompress
- 单线程顺序将明文写入与输出同目录的 `.lockdec.tmp` 临时文件（与产物同卷，保证 `rename(2)` 为原子操作）
- 同时 streaming `HMAC.update`
- EOF 后比对 HMAC footer：成功则 `rename(2)` 原子替换到最终路径，失败则 `unlink` 临时文件并报错

### 内存峰值

```
peak_memory = O((N + 1) × chunk_size)
```

与文件大小完全无关。每个 worker 持有约一个 chunk 的 buffer，单线程写端也持有一个 chunk。适合加密 GB 级文件。

### 自动调参

用户未显式指定 `--chunk-size` 或 `-j` 时，由 `memory` 模块根据可用内存自适应推荐：

- Linux：`sysconf(_SC_AVPHYS_PAGES)`
- macOS：`sysctl` 系列调用
- 均失败：退保守值（512 MiB 可用 / 1 GiB chunk 预算）

推荐值 clamp 规则：
- `chunk_size`：`[256 KiB, 4 MiB]` 且为 16 的倍数
- `jobs`：`[1, hardware_concurrency]`，每个 worker 预留约 `4 × chunk_size` 字节预算

用户可显式 `--chunk-size <bytes>` 或 `-j <N>` 覆盖自动推荐；`-v` 会在 stderr 打印实际使用的值：

```
[memory] available=2048 MiB; chunk_size=1024 KiB; jobs=4
```

### `.tmp` 文件约定

解密临时文件命名为 `<output>.lockdec.tmp`，与最终产物同目录（同文件系统），保证 `rename(2)` 为原子操作。

- 正常完成（HMAC 通过）：`rename(2)` .tmp → 最终路径
- HMAC 失败或解密中断：`unlink` 清理 .tmp
- 进程异常退出（SIGKILL、系统崩溃）：.tmp 文件残留，需要用户手动清理（没有 pid/lock 文件机制）

## 项目结构

```
.
├── CMakeLists.txt           # 构建配置（FetchContent lz4/zstd/ftxui、ThinLTO、LLD）
├── CMakePresets.json        # presets: default / debug / aarch64-static
├── cmake/
│   └── aarch64-linux-gnu.cmake  # aarch64 cross toolchain (-static-pie, multiarch .a)
├── .clang-format
├── include/ae-locker/
│   ├── constants.hpp        # 文件格式常量、scrypt 默认参数
│   ├── endian.hpp           # big-endian load/store 辅助
│   ├── errors.hpp           # ExitCode 枚举 + 自定义 exception 类
│   ├── kdf.hpp              # scrypt KDF 接口
│   ├── crypto.hpp           # 加密/解密接口（AES-256-CTR / GCM、IV 派生）
│   ├── compress.hpp         # 压缩接口（LZ4 / zstd）
│   ├── container.hpp        # FileHeader 结构 + HeaderWriter/Reader
│   ├── memory.hpp           # 可用内存检测 + chunk_size/jobs 自动推荐
│   ├── progress.hpp         # 进度条封装（手写 ASCII 渲染器）
│   ├── safe.hpp             # 三种口令来源模式（交互 / 文件 / env）
│   ├── term.hpp             # termios ECHO 切换
│   ├── i18n.hpp             # Lang/Str 枚举 + tr() 表驱动本地化
│   ├── cli.hpp              # cli_main() 入口
│   ├── cli_dispatch.hpp     # 子命令 dispatch（encrypt/decrypt/list）+ 提示文案
│   ├── completion.hpp       # `--completion <shell>` 输出 bash/zsh/fish 脚本
│   ├── repl.hpp            # `--cli` REPL 入口（readline / getline fallback）
│   └── tui.hpp             # `--tui` 入口（ftxui wizard / file browser）
├── src/
│   ├── main.cpp             # 1 行委派：`return ae_locker::cli_main(argc, argv);`
│   ├── kdf.cpp              # scrypt via EVP_KDF (OpenSSL 3.x)
│   ├── crypto.cpp           # AES-256-CTR 并行 + AES-256-GCM 文件名
│   ├── compress.cpp         # LZ4/zstd block-API 压缩封装
│   ├── container.cpp        # header 序列化/反序列化 + v1/v2 兼容
│   ├── memory.cpp           # sysconf/sysctl 可用内存检测 + 调参
│   ├── progress.cpp         # 手写进度条渲染器（per-file + overall，ASCII `[=====>]`）
│   ├── safe.cpp             # 口令输入处理（getpass / 文件 / env）
│   ├── term.cpp             # termios 封装
│   ├── i18n.cpp             # Lang/Str 表 + `tr()` 实现 + 探测逻辑
│   ├── cli.cpp              # 位置参数解析 + 顶层 dispatch
│   ├── cli_dispatch.cpp     # 子命令实现（encrypt/decrypt/list/auto 批量）
│   ├── completion.cpp       # bash/zsh/fish 补全脚本拼装
│   ├── repl.cpp             # readline 集成 + Tab completer
│   └── tui.cpp              # ftxui 主菜单 + 多步 wizard + 文件浏览器
├── scripts/
│   └── smoke-tui.sh         # TUI 冒烟测试（8 步）
├── dist/arch/{x86_64,aarch64}/ae-locker  # 产物副本（gitignore 实物 binary；只保留目录占位）
├── build/                   # default preset 产物（gitignore）
└── build-aarch64/           # aarch64-static preset 产物（gitignore）
```

## 安全说明

- 无法提供"前向安全"；口令强度决定一切——建议 ≥ 12 位混合字符
- 从文件/环境变量读口令默认禁用：文件系统日志、core dump、`/proc/<pid>/environ` 都可能泄漏
- 解密时先将明文写入与输出同目录的 `.lockdec.tmp` 临时文件，边解密边 streaming HMAC；全部 chunk 处理完、HMAC 与 footer 比对成功后，用 `rename(2)` 原子替换到最终路径；若比对失败则 `unlink` 临时文件并报错。进程异常退出留下的 `.tmp` 不会被当作正式产物（崩在 HMAC 比对之前也会被清理）
- `RAND_bytes` 来自 OpenSSL 默认随机源（getrandom/CSPRNG）
- 未提供密钥轮换/多 recipient/密钥托管；适合个人文件加密场景

## 跨架构产物 (`dist/arch/`)

通过 `cmake --preset aarch64-static` 可在 x86_64 主机为 aarch64 Linux 交叉编译一
个 **single static-pie binary**。两个架构的产物可以并存在 `dist/arch/<arch>/ae-locker`:

```
dist/
└── arch/
    ├── x86_64/ae-locker        ← cmake --preset default 的产出（动态链接）
    └── aarch64/ae-locker       ← cmake --preset aarch64-static 的产出（全静态）
```

| 架构 | preset | 链接方式 | 体积 | 大小依赖 |
|---|---|---|---|---|
| x86_64  | `default`        | 动态 (OpenSSL / readline / glibc / libstdc++) | ~1.7 MB | 目标机需装同版本 OpenSSL 3.x / readline |
| aarch64 | `aarch64-static` | 全静态 (`-static-pie`)，无任何 `NEEDED` 项 | ~11 MB | 无依赖，拷过去就跑 |

### 支持范围

- **x86_64 产物**：标准 x86_64 Linux（glibc 2.31+，OpenSSL 3.x）。在 Debian/Ubuntu/RHEL/Fedora 等标准发行版上测试通过。
- **aarch64 产物**：标准 aarch64 Linux（glibc 2.31+），**包括但不限于**：

  - Debian/Ubuntu/Raspberry Pi OS 64-bit / Alpine aarch64 glibc 版本 / 任何 aarch64 Linux 发行版
  - 树莓派 4/5 (aarch64 Raspberry Pi OS)
  - aarch64 服务器 / 云实例 / 嵌入式 Linux 主板（需 glibc 2.31+）

### 不支持的平台 — Termux / Android

`dist/arch/aarch64/ae-locker` **不能在 Termux / Android 上运行**。这不是构建参数可调
的 toolchain 限制，而是 glibc 与 Bionic 的根本架构错配：

1. 我们的 arm64 binary 静态链接 **glibc**，其 `_start` 会调用 glibc 的
   `__libc_start_main` 自举逻辑（应用 RELA 重定位、初始化 TLS、跑 preinit
   arrays 等）。
2. Android 自 5.0 起把 `e_type=DYN`（PIE）binary 强制路由给 Bionic 的
   `linker64` 处理。`linker64` 在跳 `_start` 之前已经做了一遍相同的执行环境
   初始化（自己应用 RELA 重定位、初始化 Bionic TLS、跑 `DT_INIT_ARRAY`
   构造函数）。
3. 然后 `linker64` 跳 binary 的 `_start`，glibc 自举逻辑再做第二次重定位
   / 第二次 TLS 初始化，与 Bionic 已经做好的状态冲突 → 进程立刻 segfault
   （用户场景下表现为 `ae-locker --help` 直接段错误，无 error message）。

前面为了让 binary 通过 Bionic 的两个硬性边界检查所做的工作（提交
`9cd5813` 的 `-static-pie` 改 e_type=DYN；提交 `3bbf66e` 的 alignas(64)
thread_local 哑变量抬 PT_TLS p_align 到 64）解决了 Bionic 的「PIE-only」与
「TLS 对齐 64」拒绝，但解决不掉后面的 glibc/Bionic 双 libc 互斥。

要在 Termux/Android 上跑 `AE-Locker`，需要用 Android NDK（Bionic libc）重新交叉
构建一个 native Bionic binary，或在 Termux 内部直接 `clang++` 编译——两条都
是另一条独立 build path，未包含在当前 preset 中。

## 限制

- 经 v2 流式重写，内存峰值与文件大小无关，固定为 `O((N+1) × chunk_size)`；不存在 64 GiB 硬上限（也不再设 MAX_PLAINTEXT_BYTES 限制）
- 未支持增量加密、流式 stdin/stdout
- v2 格式已实装;v1 文件只读兼容(由 HeaderReader 自动归一化),写路径永远输出 v2
- 压缩比会泄露部分文件信息(类型/熵),对极敏感场景可保留 `--compress none`
- 仅 Linux/macOS 测试通过（依赖 POSIX termios）
- aarch64 交叉构建产物 (`dist/arch/aarch64/ae-locker`) 支持标准 glibc aarch64
  Linux；不支持 Termux / Android（glibc 与 Bionic 双 libc 不可共存，详见
  上文「不支持的平台」）

## 许可证

AE-Locker 采用 [GPLv3+](LICENSE) 协议。完整文本请见仓库根目录的 [LICENSE](LICENSE) 文件。

- 加密算法：AES-256-CTR / AES-256-GCM / HMAC-SHA256（OpenSSL，Apache-2.0）
- 压缩：LZ4 (BSD-2-Clause) / zstd (GPLv2+BSD dual)
- TUI 框架：ftxui (MIT)
- Readline：GPLv3+
- 上述依赖均与 GPLv3+ 兼容

# lock

`lock` 是一个用 C++20 编写的命令行文件加密工具，使用 **AES-256-CTR** 对文件内容做多线程并行加密，使用 **AES-256-GCM** 对原始文件名加密（使其在加密后不可见），并以 **HMAC-SHA256** 对整个文件做完整性认证。密钥通过 **scrypt** KDF 从用户口令派生。支持可选的 **LZ4 / zstd** 压缩-后-加密(compress-then-encrypt):通过 `--compress` / `-z` / `--fast` 在加密前对每个 chunk 独立压缩,解密时自动识别压缩算法并还原。

构建工具链：**Clang + LLD + ThinLTO + Ninja + CMake**。

## 特性

- **可选压缩**:加密前对每个 chunk 独立做 LZ4 或 zstd 压缩;压缩与加密均在 worker 线程中并行执行;解密时根据 header 自动选择解压算法(v1 文件保持原样可读)
- **AES-256-CTR** 批量加密，可并行化（每 chunk 独立 IV）
- **AES-256-GCM** 仅用于文件名加密（小数据带认证）
- **scrypt** KDF 从口令派生 64 字节密钥材料：32 字节 `file_key` + 32 字节 `hmac_key`
- **HMAC-SHA256** 覆盖 `header || ciphertext` 作为尾部认证脚
- **文件名不可见**：原始文件名在 header 中只以密文形式存在；解密时从 header 还原
- **多线程**：单文件内 `N` 个 compress worker 并行（`-j N` 控制；encrypt 步骤因 v2 IV 需累积 CT size 为单线程串行），多文件之间也并行
- **进度条**：每文件独立 + Overall 总进度（基于 `indicators` 库）
- **多种 CLI 风格**：子命令、`-c flag`、`--cli` 交互式
- **多种口令来源**：交互式（默认）、文件（`-p`，需 `--no-safe`）、环境变量（`--password-env-var`，需 `--no-safe`）
- **输出不覆盖**：若 `foo.txt.locked` 已存在，加密会拒绝执行并报错
- **安全护栏**：从文件/环境变量读口令默认拒绝执行，需显式 `--no-safe` 确认

## 构建

依赖：
- **Clang 16+**（C++20.coroutine/`std::span`）
- **LLD**（链接器，ThinLTO 后端）
- **Ninja**
- **CMake 3.16+**
- **OpenSSL 3.x**（提供 `EVP_KDF_scrypt`、`EVP_MAC`）
- **LZ4 v1.9.4** 和 **zstd v1.5.7** 通过 CMake FetchContent 自动下载构建(无需系统预装);首次 `cmake --preset default` 会从 GitHub 拉取

```bash
cmake --preset default       # 一次性配置（首跑会 FetchContent 拉取 indicators）
cmake --build build          # 增量编译
./build/lock --version
```

`CMakePresets.json` 默认使用 `clang++` + Ninja 生成器，并启用：
- `-flto=thin` + `-Wl,--thinlto-cache-dir=build/.lto-cache`
- `-fuse-ld=lld`
- `-Wall -Wextra -Wpedantic -Werror -Wconversion -Wimplicit-int-conversion`

## 快速开始

```bash
# 加密（交互式输入口令）
./build/lock encrypt secret.txt
# → secret.txt.locked

# 解密（口令同上）
./build/lock decrypt secret.txt.locked -o ./out/
# → ./out/secret.txt  （文件名从 header 还原）

# 查看加密文件元数据（不解密）
./build/lock list secret.txt.locked
```

多文件并行加密：

```bash
./build/lock encrypt a.txt b.txt c.txt -j 8
```

## 本地化 (Locale / Language)

`lock` 内置中英双语支持。语言按以下优先级自动检测，可用 `--lang` 强制覆盖；全程无第三方 i18n 库依赖。

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
./build/lock --lang zh encrypt secret.txt

# 仅影响本次运行的环境变量路由
LC_ALL=zh_CN.UTF-8 ./build/lock encrypt secret.txt

# 显示语言探测行
./build/lock encrypt secret.txt -v

# 关掉彩色与光标 ANSI
./build/lock --no-color encrypt secret.txt -o ./out/

# 管道模式：自动检测 stdin 是否为 tty，非 tty 时不关回显
printf 'pw\npw\n' | ./build/lock encrypt secret.txt
```

### 退出代码表

`cli_main` 仍只暴露 `int` 返回值（公开签名不变），但内部按场景分别返回以下退出码：

| 退出码 | 含义                                                           | 触发场景                                                                          |
|:-----:|:---------------------------------------------------------------|:--------------------------------------------------------------------------------|
|   0   | 成功 (Ok)                                                       | 加密/解密/list 正常完成                                                           |
|   2   | 参数错误 (Arg)                                                  | 未知命令 / 缺少 flag 值 / 不支持的 flag 值（`--lang fr` / `--compress bogus` 等）/ 密码不匹配、空密码 / 无可加密文件 / 无输入文件 / `--max-depth` 未与 `--auto` 一起用 / `--auto` 给的目录不存在 |
|   3   | I/O 错误 / 输入文件已存在 (Io)                                  | 目标 `.locked` 文件已存在（不覆盖护栏）/ 目录创建失败 / 文件不可读                |
|   4   | 密钥派生 / 认证失败 (Auth)                                      | 解密时密码错（HMAC 校验失败 / 文件被篡改 / salt 不匹配）                          |
|   5   | 内部不可恢复错误 (Internal)                                      | 异常落到 `cli_main` 顶层兜底分支                                                 |

`lock list` 子命令即使对"不是 `.locked` 文件"的入参也返回 0（仅打印提示），不影响脚本以退出码聚合判断其他子命令的成功/失败。

## 批量目录加密/解密（`--auto`)

`--auto <dir>` 进入批量模式：递归扫描指定目录中的所有常规文件,镜像源目录的子目录结构落到 `-o/--output-dir` 下,避免不同子目录中同名文件冲突。

```bash
# 递归加密 ./secrets 下所有文件到 ./encrypted,镜像源目录结构
./build/lock encrypt --auto ./secrets --max-depth 3 -o ./encrypted

# 递归解密:扫描 ./encrypted/*.locked 用 header 中还原的文件名输出到 ./decrypted,
# 子目录结构镜像到 ./decrypted下
./build/lock decrypt --auto ./encrypted -o ./decrypted
```

约定：

- `--auto <dir>`:递归扫描该目录。`-o/--output-dir` **必须**显式给出,作为镜像源子目录结构的输出根。
- `--max-depth <N>`:递归深度控制。`-1` = 不限(默认);`0` = 仅 `--auto` 给的目录内的直系文件;`1` = 当前层 + 一层子目录;依此类推。
- encrypt:跳过 `.locked` 结尾的文件(防止二次加密自己的产物);只对常规文件处理。
- decrypt:只处理 `.locked` 结尾的常规文件,从 header 还原原始文件名作为输出文件名。
- 跳过 symlink(防止 cycle 攻击);跳过非常规文件(socket/device/fifo)。
- 输出现在用 `[源相对路径].locked` (encrypt)  / `[源相对子目录]/[header 还原文体名]` (decrypt) 落地 `-o`,与单文件模式同样遵循"存在即拒"(不覆盖已有产物)。
- `--auto` 与位置文件参数互斥,二者只能给其一;`--max-depth` 单独给出(没有 `--auto`)会报错。
- 空(无可加密/解密的文件)目录会以"no eligible files found"报错(非静默成功)。

## 三种 CLI 调用方式

| 方式 | 命令 |
|---|---|
| **子命令（默认）** | `lock encrypt <file> [options]` |
| **flag 形式** | `lock -c encrypt <file> [options]` |
| **交互式** | `lock --cli`（进入 REPL，支持 `encrypt` / `decrypt` / `list` / `quit`，以及帮助内部命令 `help` / `?` / `h`） |

### 子命令级 `--help` / `-h`

`lock --help` 输出总览；任意子命令后追加 `--help`（或 `-h`）只打印该子命令的简介、相关选项与示例，并立即以退出码 0 返回（不真正执行 encrypt/decrypt/list，即便其它参数已存在）：

```bash
lock encrypt --help    # encrypt 频专属帮助(EN)
lock decrypt --help    # decrypt 频专属帮助
lock list --help       # list 频专属帮助
lock encrypt -h        # 与 --help 完全一致
lock --lang zh encrypt --help   # 中文版 encrypt 专属帮助
lock encrypt foo.txt --help -o out -z   # --help 短路,不加密,退出 0
```

`lock help encrypt` **不**存在 —— 顶层的 `help` 仍是 unknown command（退出 2），仅在 `--cli` REPL 内部可用。

### `--cli` REPL 内部帮助命令

进入 `lock --cli` 后，REPL 接受额外的帮助命令（仅 REPL 内部，并不暴露为可执行子命令）：

| 命令 | 行为 |
|---|---|
| `help` / `?` / `h` | 打印与 `lock --help` 相同的总体帮助到 STDOUT |
| `help encrypt` / `? encrypt` / `h decrypt` / `? list` 等 | 打印对应子命令的专属帮助到 STDOUT |
| `help bogus`（或任何非 encrypt/decrypt/list 的主题） | 向 STDERR 输出本地化「未知帮助主题」错误，REPL **不**退出，仍重新提示 |

REPL 启动时会把简短提示打到 STDERR 一次，提示用户可输入 `help` / `?` / `h` 与 `quit`。`quit` / `exit` / `q` 仍以 ExitCode::Ok 结束 REPL。

## 三种口令来源

| 模式 | 用法 | 安全护栏 |
|---|---|---|
| 交互式（默认） | `lock encrypt foo.txt` 后提示输入 | 无（安全） |
| 文件 | `lock encrypt -p ./pw.txt --no-safe foo.txt` | **必须** `--no-safe` |
| 环境变量 | `LOCK_PASSWORD=xxx lock encrypt --password-env-var --no-safe foo.txt` | **必须** `--no-safe` |

`--password-env-var` 可缩写为 `-pev`。

不加 `--no-safe` 时从文件/环境变量读口令会被拒绝并报错，避免 fsync 日志、core dump、进程列表泄漏口令的风险。

## 完整选项列表

```
Commands:
  encrypt    加密一个或多个文件为 .locked 容器
  decrypt    解密一个或多个 .locked 容器
  list       打印 .locked 容器的元数据（不解密）

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

## 加密文件格式（`.locked`）

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
├── CMakeLists.txt        # 构建配置（FetchContent indicators、ThinLTO、LLD）
├── CMakePresets.json     # default preset
├── .clang-format
├── include/lock/
│   ├── constants.hpp     # 文件格式常量、scrypt 默认参数
│   ├── endian.hpp        # big-endian load/store 辅助
│   ├── kdf.hpp           # scrypt KDF 接口
│   ├── crypto.hpp        # 加密/解密接口
│   ├── safe.hpp          # 三种口令来源模式
│   ├── term.hpp          # termios ECHO 切换
│   ├── progress.hpp      # 进度条封装
│   ├── cli.hpp           # cli_main() 入口
│   ├── compress.hpp      # 压缩接口(LZ4/zstd)
│   ├── container.hpp     # FileHeader 结构 + HeaderWriter/Reader
│   ├── memory.hpp        # 内存检测 + 流式参数推荐
├── src/
│   ├── kdf.cpp           # scrypt via EVP_KDF (OpenSSL 3.x)
│   ├── container.cpp     # header 序列化/反序列化
│   ├── crypto.cpp        # AES-256-CTR 并行 + AES-256-GCM 文件名
│   ├── safe.cpp          # 口令输入处理
│   ├── term.cpp          # termios 封装
│   ├── progress.cpp      # indicators 进度条
│   ├── cli.cpp           # CLI dispatcher + REPL
│   ├── compress.cpp      # LZ4/zstd block-API 压缩封装
│   ├── memory.cpp        # 可用内存检测 + chunk_size/jobs 自动推荐
│   └── main.cpp          # 1 行委派
└── build/                # 生成产物（gitignore）
```

## 安全说明

- 无法提供"前向安全"；口令强度决定一切——建议 ≥ 12 位混合字符
- 从文件/环境变量读口令默认禁用：文件系统日志、core dump、`/proc/<pid>/environ` 都可能泄漏
- 解密时先将明文写入与输出同目录的 `.lockdec.tmp` 临时文件，边解密边 streaming HMAC；全部 chunk 处理完、HMAC 与 footer 比对成功后，用 `rename(2)` 原子替换到最终路径；若比对失败则 `unlink` 临时文件并报错。进程异常退出留下的 `.tmp` 不会被当作正式产物（崩在 HMAC 比对之前也会被清理）
- `RAND_bytes` 来自 OpenSSL 默认随机源（getrandom/CSPRNG）
- 未提供密钥轮换/多 recipient/密钥托管；适合个人文件加密场景

## 限制

- 经 v2 流式重写，内存峰值与文件大小无关，固定为 `O((N+1) × chunk_size)`；不存在 64 GiB 硬上限（也不再设 MAX_PLAINTEXT_BYTES 限制）
- 未支持增量加密、流式 stdin/stdout
- v2 格式已实装;v1 文件只读兼容(由 HeaderReader 自动归一化),写路径永远输出 v2
- 压缩比会泄露部分文件信息(类型/熵),对极敏感场景可保留 `--compress none`
- 仅 Linux/macOS 测试通过（依赖 POSIX termios）

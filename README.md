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
- **多线程**：单文件内 `N` 个 chunk 并行（默认硬件并发，`-j N` 可配），多文件之间也并行
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

## 三种 CLI 调用方式

| 方式 | 命令 |
|---|---|
| **子命令（默认）** | `lock encrypt <file> [options]` |
| **flag 形式** | `lock -c encrypt <file> [options]` |
| **交互式** | `lock --cli`（进入 REPL，支持 `encrypt` / `decrypt` / `list` / `quit`） |

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
      --version                打印版本
  -h, --help                   打印帮助
```

## 加密文件格式（`.locked`）

```
+────────────────+──────────────────────────────────────+
│ Fixed Header   │ v1: 112 bytes; v2: 120 bytes          |
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

### Fixed Header（120 字节，big-endian）

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
├── src/
│   ├── kdf.cpp           # scrypt via EVP_KDF (OpenSSL 3.x)
│   ├── container.cpp     # header 序列化/反序列化
│   ├── crypto.cpp        # AES-256-CTR 并行 + AES-256-GCM 文件名
│   ├── safe.cpp          # 口令输入处理
│   ├── term.cpp          # termios 封装
│   ├── progress.cpp      # indicators 进度条
│   ├── cli.cpp           # CLI dispatcher + REPL
│   ├── compress.cpp      # LZ4/zstd block-API 压缩封装
│   └── main.cpp          # 1 行委派
└── build/                # 生成产物（gitignore）
```

## 安全说明

- 无法提供"前向安全"；口令强度决定一切——建议 ≥ 12 位混合字符
- 从文件/环境变量读口令默认禁用：文件系统日志、core dump、`/proc/<pid>/environ` 都可能泄漏
- 解密时 HMAC 验证在写入明文**之前**完成，避免未认证数据落盘
- `RAND_bytes` 来自 OpenSSL 默认随机源（getrandom/CSPRNG）
- 未提供密钥轮换/多 recipient/密钥托管；适合个人文件加密场景

## 限制

- 单文件加密前会整体读入内存（已加 64 GiB 上限保护）
- 未支持增量加密、流式 stdin/stdout
- v2 格式已实装;v1 文件只读兼容(由 HeaderReader 自动归一化),写路径永远输出 v2
- 压缩比会泄露部分文件信息(类型/熵),对极敏感场景可保留 `--compress none`
- 仅 Linux/macOS 测试通过（依赖 POSIX termios）

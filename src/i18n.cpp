#include <lock/i18n.hpp>

#include <array>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <unistd.h>

namespace lock {

namespace {

// Both arrays must have exactly Str::Str_sentinel entries, in the same
// index order as enum class Str in i18n.hpp.  A `static_assert` below
// cross-checks the length.
//
// Some entries contain a single literal `%s` token (e.g. flag-taking error
// messages).  Callers splice the runtime value in via std::string
// concatenation done by the call site (we deliberately do NOT use printf
// formatting here — plain substring find/replace keeps the helpers tiny
// and avoids pulling in <format>).

// clang-format off
constexpr std::array<const char*, static_cast<size_t>(Str::Str_sentinel)> en_strings = {
    // ---- Help / usage ----------------------------------------------------
    "lock 1.0.0 — AES-256-CTR + HMAC-SHA256 file encryption\n",
    "Encrypt files into tamper-evident .locked containers.\n",
    "Usage:\n"
    "  lock <command> [options] <file> [<file> ...]\n"
    "  lock -c <command> [options] <file> [<file> ...]\n"
    "  lock --cli\n"
    "  lock --help | --version\n",
    "encrypt    Encrypt one or more files into .locked containers\n"
    "           (supports --auto <dir> for recursive directory batch mode)\n",
    "decrypt    Decrypt one or more .locked containers\n"
    "           (supports --auto <dir> for recursive directory batch mode)\n",
    "list       Print the metadata of a .locked container without decrypting\n",
    "Common Options:\n",
    "Encrypt-only Options:\n",
    "Decrypt-only Options:\n",
    "Examples:\n",
    "  -p, --password-file <path>   Read password from <path> (requires --no-safe)\n",
    "      --password-env-var       Read password from $LOCK_PASSWORD (requires --no-safe)\n",
    "      --no-safe                Acknowledge unsafe password sources\n",
    "  -j, --jobs <N>               Per-file worker threads (default: hardware_concurrency)\n",
    "  -o, --output-dir <dir>       Output directory (default: same dir as input file).\n"
    "                               In --auto mode this becomes the root of the mirrored\n"
    "                               source subdirectory tree (must be explicit).\n",
    "      --chunk-size <bytes>     Encryption chunk size (default 1 MiB; >=4096 and /16)\n",
    "      --compress <algo>          Compress before encrypt: none|lz4|zstd (default: none)\n",
    "  -z                            Shorthand for --compress zstd (balanced)\n",
    "      --fast                     Shorthand for --compress lz4 (fast, low ratio)\n",
    "      --level <N>                Compression level: zstd 1..22 (default 3); lz4 ignores\n",
    "      --auto <dir>              Batch mode: recursively scan <dir>.\n"
    "                               Requires -o/--output-dir. Exclusive with positional files.\n",
    "      --max-depth <N>           --auto recursion depth: -1 = unlimited (default),\n"
    "                               0 = only direct files of --auto dir, 1 = +1 subdir, etc.\n",
    "  -v, --verbose                Print extra status to stderr\n",
    "  -q, --quiet                  Suppress progress bars (errors still shown)\n",
    "      --lang <en|zh>           Override the UI language (default: auto-detect)\n",
    "      --no-color                Disable ANSI colour in stderr diagnostics\n",
    "      --version                Print version and exit\n",
    "  -h, --help                   Print this help and exit\n",
    "# Encrypt a single file (interactive password prompt)\n"
    "  lock encrypt secret.txt\n",
    "# Decrypt with -o placing the restored file in ./out/\n"
    "  lock decrypt secret.txt.locked -o ./out/\n",
    "# Recursively encrypt all files under ./secrets (mirror subdirs into ./encrypted)\n"
    "  lock encrypt --auto ./secrets --max-depth 3 -o ./encrypted\n",
    "# Inspect a .locked container's metadata without decrypting\n"
    "  lock list secret.txt.locked\n",
    "Decrypt also accepts --auto <dir> and --max-depth <N> (see Encrypt-only Options).\n",
    "Run `lock <cmd> --help` for per-subcommand details.\n",
    "Encrypt one or more files into tamper-evident .locked containers.\n"
    "Supports a single file, a list of files, or recursive --auto batch mode.\n",
    "Decrypt one or more .locked containers, restoring the original file(s).\n"
    "Supports a single file, a list of files, or recursive --auto batch mode.\n",
    "Print metadata of one or more .locked containers without decrypting.\n"
    "Safe to run on any file; non-.locked inputs are reported and skipped.\n",
    "# Encrypt a single file\n"
    "  lock encrypt secret.txt\n"
    "# Compress-then-encrypt with zstd (-z) and a password file\n"
    "  lock encrypt secret.txt -p pw.txt --no-safe -z -o ./out/\n"
    "# Recursive batch encrypt mirroring the source tree\n"
    "  lock encrypt --auto ./secrets --max-depth 3 -o ./encrypted\n",
    "# Decrypt a single container into ./out/\n"
    "  lock decrypt secret.txt.locked -o ./out/\n"
    "# Decrypt with a password file\n"
    "  lock decrypt secret.txt.locked -p pw.txt --no-safe -o ./out/\n"
    "# Recursive batch decrypt mirroring the source tree\n"
    "  lock decrypt --auto ./encrypted -o ./decrypted\n",
    "# Inspect one or more .locked containers (no password needed)\n"
    "  lock list secret.txt.locked\n"
    "# Inspect every .locked file in a directory\n"
    "  lock list file1.locked file2.locked\n"
    "# Safe to run on a non-.locked file (reported and skipped)\n"
    "  lock list plain.txt\n",

    // ---- Common error / status labels ------------------------------------
    "error: ",
    "warning: ",
    "unknown command '",
    "flag %s requires a value",
    "flag %s requires an integer value",
    "flag %s requires a non-negative integer",
    "flag %s value out of range [%s, %s]",
    "invalid --compress value '%s' (must be: none|lz4|zstd)",
    "unknown flag '%s'",
    "-c requires a command",
    "no input files specified",
    "--chunk-size must be at least 4096",
    "--chunk-size must be a multiple of 16",
    "--auto specified more than once",
    "--auto is not supported by the 'list' command",
    "--auto <dir> is exclusive with positional file arguments — choose one",
    "--auto dir '%s' does not exist or is not a directory",
    "--auto requires explicit -o/--output-dir",
    "--max-depth requires --auto",
    "--max-depth must be >= -1 (-1 means unlimited)",
    "--level value out of range [1, 22]",
    "invalid --lang value '%s' (must be en or zh)",
    "'%s' already exists. Remove it or choose a different output directory.\n",
    "output directory '%s' cannot be created: %s",
    "failed to scan --auto dir '%s'",
    "no eligible files found under '%s'",
    "'%s' is not a .locked file (bad magic)",
    "error: ",
    "unknown help topic '%s' (choose: encrypt|decrypt|list)",

    // ---- Crypto / IO classification error messages ------------------------
    "HMAC verification failed",
    "GCM authentication failed",
    "scrypt failed",
    "RAND_bytes returned short buffer",
    "input file '%s' does not exist or cannot be opened",
    "I/O error",

    // ---- Password / safe --------------------------------------------------
    "Enter password (input hidden): ",
    "Confirm password: ",
    "passwords do not match",
    "password cannot be empty",
    "Reading password from a file is considered unsafe "
    "(file contents may leak via fsync logs / core dumps / "
    "process listings). "
    "Re-run with --no-safe to override.",
    "Reading password from an environment variable is considered "
    "unsafe (env vars leak via /proc/PID/environ, ps -E, and "
    "child processes). "
    "Re-run with --no-safe to override.",
    "password read from file — ensure the file is not logged",
    "password read from environment variable '%s' — env vars may leak via /proc/PID/environ",
    "cannot open password file: %s",
    "password file is empty: %s",
    "password file exceeds 4 KiB limit",
    "password exceeds maximum length",
    "environment variable '%s' is not set",
    "environment variable '%s' is empty",
    "read() from tty failed",
    "invalid password mode",
    "cannot open /dev/tty — interactive password unavailable (stdin redirected?)",
    "tcgetattr failed on tty",
    "tcsetattr failed disabling echo",

    // ---- Progress bar labels ---------------------------------------------
    "Overall: ",
    "Encrypting ",
    "Decrypting ",
    "done",
    "[pending] ",

    // ---- `list` command field labels --------------------------------------
    "File: ",
    "  (not a .locked file)\n",
    "  magic:         ENCF0001v1\n",
    "  version:       ",
    "  algorithm:     AES-256-CTR + HMAC-SHA256 (0x",
    "  KDF:           scrypt (N=",
    "  salt:          ",
    "  base_iv:       ",
    "  original_size: ",
    "  chunk_size:    ",
    "  chunk_count:   ",
    "  compression:   ",
    "  stored_size:   ",
    "  filename_len:  ",
    "  data_offset:   ",
    "  file_size:     ",
    "  overhead:      ",
    "  error: ",

    // ---- Verbose / status -------------------------------------------------
    "[lang] detected=",
    "[memory] available=",

    // ---- Version + interactive REPL --------------------------------------
    "lock 1.0.0",
    "lock interactive mode\n",
    "> ",
    "Commands: encrypt, decrypt, list, quit\n",
    "  unknown command '",
    "' — try 'encrypt', 'decrypt', 'list', or 'quit'\n",
    "'——请使用 'encrypt'、'decrypt'、'list' 或 'quit'\n",
    "  file path (empty line to finish): ",
    "  no files specified — aborted\n",
    "Enter `help` for command help, `quit` to exit. Inside the REPL you can also type `?` or `h`.\n",

    // ---- Completion script generation ----
    "missing shell argument (use: bash|zsh|fish)",
    "unsupported shell '%s' (choose: bash, zsh, fish)",

    // ---- REPL readline ----
    "[repl] readline not found at build time — using line mode (no history, no Tab completion)\n",

    // ---- TUI ----
    "TUI mode requires an interactive terminal (tty)",
    "TUI mode requires colour support (don't use --no-color or NO_COLOR)",
    "lock TUI Main Menu",
    "Encrypt",
    "Decrypt",
    "List",
    "Quit",
    "(This submenu is not implemented yet)",
    "Press Enter to return to main menu",
};

constexpr std::array<const char*, static_cast<size_t>(Str::Str_sentinel)> zh_strings = {
    // ---- Help / usage ----------------------------------------------------
    "lock 1.0.0 — AES-256-CTR + HMAC-SHA256 文件加密\n",
    "将文件加密为带完整性认证的 .locked 容器。\n",
    "用法:\n"
    "  lock <子命令> [选项] <文件> [<文件> ...]\n"
    "  lock -c <子命令> [选项] <文件> [<文件> ...]\n"
    "  lock --cli\n"
    "  lock --help | --version\n",
    "encrypt    加密一个或多个文件为 .locked 容器\n"
    "           (支持 --auto <dir> 递归目录批量模式)\n",
    "decrypt    解密一个或多个 .locked 容器\n"
    "           (支持 --auto <dir> 递归目录批量模式)\n",
    "list       打印 .locked 容器的元数据(不解密)\n",
    "通用选项:\n",
    "仅 encrypt 的选项:\n",
    "仅 decrypt 的选项:\n",
    "示例:\n",
    "  -p, --password-file <path>   从文件读取口令(需要 --no-safe)\n",
    "      --password-env-var       从 $LOCK_PASSWORD 读取口令(需要 --no-safe)\n",
    "      --no-safe                确认使用不安全的口令来源\n",
    "  -j, --jobs <N>               每文件 worker 线程数(默认 hardware_concurrency)\n",
    "  -o, --output-dir <dir>       输出目录(默认与输入同目录)。\n"
    "                               在 --auto 模式下作为镜像源子目录结构的输出根\n"
    "                               (必须显式指定)。\n",
    "      --chunk-size <bytes>     加密分块大小(默认 1 MiB;需 ≥4096 且为 16 的倍数)\n",
    "      --compress <algo>          加密前压缩:none|lz4|zstd(默认 none)\n",
    "  -z                            --compress zstd 的简写(均衡压缩)\n",
    "      --fast                     --compress lz4 的简写(快速,压缩比低)\n",
    "      --level <N>                压缩级别:zstd 1..22(默认 3);lz4 忽略\n",
    "      --auto <dir>              批量模式:递归扫描 <dir>。\n"
    "                               需要 -o/--output-dir。与位置参数互斥。\n",
    "      --max-depth <N>           --auto 递归深度:-1 = 不限(默认),\n"
    "                               0 = 仅 --auto 目录直系文件,1 = +1 层子目录,以此类推。\n",
    "  -v, --verbose                在 stderr 打印额外状态\n",
    "  -q, --quiet                  关闭进度条(错误仍输出)\n",
    "      --lang <en|zh>           覆盖 UI 语言(默认:自动检测)\n",
    "      --no-color                关闭 stderr 诊断中的 ANSI 颜色\n",
    "      --version                打印版本并退出\n",
    "  -h, --help                   打印帮助并退出\n",
    "# 加密单个文件(交互式输入口令)\n"
    "  lock encrypt secret.txt\n",
    "# 解密并用 -o 把还原的文件放到 ./out/\n"
    "  lock decrypt secret.txt.locked -o ./out/\n",
    "# 递归加密 ./secrets 下所有文件(子目录结构镜像到 ./encrypted)\n"
    "  lock encrypt --auto ./secrets --max-depth 3 -o ./encrypted\n",
    "# 查看一个 .locked 容器的元数据(不解密)\n"
    "  lock list secret.txt.locked\n",
    "decrypt 也支持 --auto <dir> 与 --max-depth <N>(参见\"仅 encrypt 的选项\")。\n",
    "运行 `lock <子命令> --help` 查看该子命令的详细帮助。\n",
    "将一个或多个文件加密为带完整性认证的 .locked 容器。\n"
    "支持单个文件、文件列表,以及递归 --auto 批量模式。\n",
    "解密一个或多个 .locked 容器,还原原始文件。\n"
    "支持单个文件、文件列表,以及递归 --auto 批量模式。\n",
    "打印一个或多个 .locked 容器的元数据(不解密)。\n"
    "对任何文件都安全运行;非 .locked 文件会被报告并跳过。\n",
    "# 加密单个文件\n"
    "  lock encrypt secret.txt\n"
    "# 用 zstd (-z) 压缩后加密,口令从文件读取\n"
    "  lock encrypt secret.txt -p pw.txt --no-safe -z -o ./out/\n"
    "# 递归批量加密(镜像源目录结构)\n"
    "  lock encrypt --auto ./secrets --max-depth 3 -o ./encrypted\n",
    "# 解密单个容器到 ./out/\n"
    "  lock decrypt secret.txt.locked -o ./out/\n"
    "# 用口令文件解密\n"
    "  lock decrypt secret.txt.locked -p pw.txt --no-safe -o ./out/\n"
    "# 递归批量解密(镜像源目录结构)\n"
    "  lock decrypt --auto ./encrypted -o ./decrypted\n",
    "# 查看一个或多个 .locked 容器的元数据(无需口令)\n"
    "  lock list secret.txt.locked\n"
    "# 查看目录下多个 .locked 文件\n"
    "  lock list file1.locked file2.locked\n"
    "# 对非 .locked 文件安全运行(报告并跳过)\n"
    "  lock list plain.txt\n",

    // ---- Common error / status labels ------------------------------------
    "错误: ",
    "警告: ",
    "未知命令 '",
    "flag %s 需要一个值",
    "flag %s 需要一个整数值",
    "flag %s 需要一个非负整数",
    "flag %s 的值超出范围 [%s, %s]",
    "无效的 --compress 值 '%s'(取值: none|lz4|zstd)",
    "未知 flag '%s'",
    "-c 需要一个子命令",
    "未指定输入文件",
    "--chunk-size 至少为 4096",
    "--chunk-size 必须是 16 的倍数",
    "--auto 重复指定",
    "--auto 不被 'list' 子命令支持",
    "--auto <dir> 与位置文件参数互斥——只能二选一",
    "--auto 目录 '%s' 不存在或不是目录",
    "--auto 需要显式的 -o/--output-dir",
    "--max-depth 必须与 --auto 一起使用",
    "--max-depth 必须 >= -1(-1 表示不限)",
    "--level 的值超出范围 [1, 22]",
    "无效的 --lang 值 '%s'(取值: en 或 zh)",
    "'%s' 已存在。请删除该文件或选择不同的输出目录。\n",
    "无法创建输出目录 '%s': %s",
    "扫描 --auto 目录 '%s' 失败",
    "在 '%s' 下未找到符合条件的文件",
    "'%s' 不是 .locked 文件(magic 不匹配)",
    "错误: ",
    "未知帮助主题 '%s'(取值: encrypt|decrypt|list)",

    // ---- Crypto / IO classification error messages ------------------------
    "HMAC 校验失败",
    "GCM 认证失败",
    "scrypt 失败",
    "RAND_bytes 返回的 buffer 不足",
    "输入文件 '%s' 不存在或无法打开",
    "I/O 错误",

    // ---- Password / safe --------------------------------------------------
    "请输入密码(输入不可见): ",
    "请再次输入以确认: ",
    "两次输入的密码不一致",
    "密码不能为空",
    "从文件读取口令被认为是不安全的"
    "(文件内容可能通过 fsync 日志 / core dump / "
    "进程列表泄漏)。"
    "如需强制使用,请加 --no-safe。",
    "从环境变量读取口令被认为是不安全的"
    "(环境变量会通过 /proc/PID/environ、ps -E 和"
    "子进程泄漏)。"
    "如需强制使用,请加 --no-safe。",
    "口令从文件读取——请确保该文件未被日志记录",
    "口令从环境变量 '%s' 读取——环境变量可能通过 /proc/PID/environ 泄漏",
    "无法打开口令文件: %s",
    "口令文件为空: %s",
    "口令文件超过 4 KiB 限制",
    "口令超过最大长度",
    "环境变量 '%s' 未设置",
    "环境变量 '%s' 为空",
    "从 tty 读取失败",
    "无效的口令模式",
    "无法打开 /dev/tty —— 交互式口令不可用(stdin 被重定向?)",
    "tcgetattr 在 tty 上失败",
    "tcsetattr 关闭回显失败",

    // ---- Progress bar labels ---------------------------------------------
    "总体: ",
    "加密中 ",
    "解密中 ",
    "完成",
    "[等待] ",

    // ---- `list` command field labels --------------------------------------
    "文件: ",
    "  (不是 .locked 文件)\n",
    "  magic:         ENCF0001v1\n",
    "  version:       ",
    "  algorithm:     AES-256-CTR + HMAC-SHA256 (0x",
    "  KDF:           scrypt (N=",
    "  salt:          ",
    "  base_iv:       ",
    "  original_size: ",
    "  chunk_size:    ",
    "  chunk_count:   ",
    "  compression:   ",
    "  stored_size:   ",
    "  filename_len:  ",
    "  data_offset:   ",
    "  file_size:     ",
    "  overhead:      ",
    "  错误: ",

    // ---- Verbose / status -------------------------------------------------
    "[lang] detected=",
    "[memory] available=",

    // ---- Version + interactive REPL --------------------------------------
    "lock 1.0.0",
    "lock 交互模式\n",
    "> ",
    "子命令:encrypt, decrypt, list, quit\n",
    "  未知命令 '",
    "'——请使用 'encrypt'、'decrypt'、'list' 或 'quit'\n",
    "'——请使用 'encrypt'、'decrypt'、'list' 或 'quit'\n",
    "  文件路径(空行结束): ",
    "  未指定文件——已中止\n",
    "输入 `help` 查看命令帮助,`quit` 退出。REPL 内也可以输入 `?` 或 `h`。\n",

    // ---- Completion script generation ----
    "缺少 shell 参数(可选: bash|zsh|fish)",
    "不支持的 shell '%s'(可选: bash、zsh、fish)",

    // ---- REPL readline ----
    "[repl] 编译时未发现 readline —— 使用 line 模式(无历史、无 Tab 补全)\n",

    // ---- TUI ----
    "TUI 模式需要交互式终端 (tty)",
    "TUI 模式需要彩色支持 (不要使用 --no-color 或 NO_COLOR)",
    "lock TUI 主菜单",
    "加密 (Encrypt)",
    "解密 (Decrypt)",
    "查看 (List)",
    "退出 (Quit)",
    "(本子菜单将在后续版本中实装)",
    "按回车返回主菜单",
};
// clang-format on

static_assert(en_strings.size() == zh_strings.size(),
              "en_strings and zh_strings must have identical length");
static_assert(static_cast<size_t>(Str::Str_sentinel) == en_strings.size(),
              "Str::Str_sentinel must equal the string table length");

std::atomic<Lang> g_current_lang{Lang::En};

// Tri-state colour flag.
//   0  not yet decided
//   1  enabled
//  -1  disabled (via --no-color OR a tty probe that came back negative)
std::atomic<int> g_color_state{0};

const char* const* active_strings_ptr() {
    return (g_current_lang.load(std::memory_order_relaxed) == Lang::Zh)
               ? zh_strings.data()
               : en_strings.data();
}

bool starts_with_zh_ignore_case(const char* s) {
    if (s == nullptr) {
        return false;
    }
    char c0 = static_cast<char>(std::tolower(static_cast<unsigned char>(s[0])));
    if (c0 != 'z') {
        return false;
    }
    char c1 = static_cast<char>(std::tolower(static_cast<unsigned char>(s[1])));
    return c1 == 'h';
}

bool is_color_enabled() {
    int st = g_color_state.load(std::memory_order_relaxed);
    return st == 1;
}

std::string wrap_color(std::string_view text, const char* sgr) {
    if (!is_color_enabled() || text.empty()) {
        return std::string(text);
    }
    std::string out;
    out.reserve(text.size() + 8);
    out.append(sgr);
    out.append(text.data(), text.size());
    out.append("\x1b[0m");
    return out;
}

}  // namespace

// Quick substring `%s` substitution: replace up to two `%s` placeholders in
// `tmpl` with `a` then `b`.  Used by cli.cpp to splice flag names / dirs /
// error messages into the table-driven templates.
std::string subst(std::string_view tmpl, std::string_view a) {
    std::string out{tmpl};
    if (auto pos = out.find("%s"); pos != std::string::npos) {
        out.replace(pos, 2, a.data(), a.size());
    }
    return out;
}

std::string subst2(std::string_view tmpl, std::string_view a, std::string_view b) {
    std::string out{tmpl};
    if (auto pos = out.find("%s"); pos != std::string::npos) {
        out.replace(pos, 2, a.data(), a.size());
        if (auto pos2 = out.find("%s"); pos2 != std::string::npos) {
            out.replace(pos2, 2, b.data(), b.size());
        }
    }
    return out;
}

std::string subst3(std::string_view tmpl,
                   std::string_view a,
                   std::string_view b,
                   std::string_view c) {
    std::string out{tmpl};
    size_t at = out.find("%s");
    if (at != std::string::npos) {
        out.replace(at, 2, a.data(), a.size());
        at = out.find("%s");
        if (at != std::string::npos) {
            out.replace(at, 2, b.data(), b.size());
            at = out.find("%s");
            if (at != std::string::npos) {
                out.replace(at, 2, c.data(), c.size());
            }
        }
    }
    return out;
}

void I18n::init(Lang lang) noexcept {
    g_current_lang.store(lang, std::memory_order_relaxed);
}

Lang I18n::current() noexcept {
    return g_current_lang.load(std::memory_order_relaxed);
}

const char* I18n::get(Str s) noexcept {
    const auto i = static_cast<size_t>(s);
    if (i >= static_cast<size_t>(Str::Str_sentinel)) {
        return "(missing string)";
    }
    return active_strings_ptr()[i];
}

Lang detect_lang_from_env() noexcept {
    const char* candidates[] = {
        std::getenv("LC_ALL"),
        std::getenv("LC_MESSAGES"),
        std::getenv("LANG"),
    };
    for (const char* v : candidates) {
        if (v != nullptr && v[0] != '\0') {
            return starts_with_zh_ignore_case(v) ? Lang::Zh : Lang::En;
        }
    }
    return Lang::En;
}

EnvLangSource probe_env_lang_source() noexcept {
    struct Probe {
        const char* name;
        const char* value;
    };
    Probe probes[] = {
        {"LC_ALL",     std::getenv("LC_ALL")},
        {"LC_MESSAGES", std::getenv("LC_MESSAGES")},
        {"LANG",       std::getenv("LANG")},
    };
    for (const auto& p : probes) {
        if (p.value != nullptr && p.value[0] != '\0') {
            EnvLangSource out;
            out.var_name = p.name;
            out.value   = p.value;
            out.detected =
                starts_with_zh_ignore_case(p.value) ? Lang::Zh : Lang::En;
            return out;
        }
    }
    EnvLangSource out;
    out.var_name = "";
    out.value   = "";
    out.detected = Lang::En;
    return out;
}

std::string color_error(std::string_view text) {
    return wrap_color(text, "\x1b[31m");
}
std::string color_warn(std::string_view text) {
    return wrap_color(text, "\x1b[33m");
}
std::string color_ok(std::string_view text) {
    return wrap_color(text, "\x1b[32m");
}
std::string color_path(std::string_view text) {
    return wrap_color(text, "\x1b[36m");
}
std::string color_none(std::string_view text) {
    return std::string(text);
}

void disable_color() noexcept {
    g_color_state.store(-1, std::memory_order_relaxed);
}

bool color_enabled() noexcept {
    return g_color_state.load(std::memory_order_relaxed) > 0;
}

void enable_color_if_tty() noexcept {
    int cur = g_color_state.load(std::memory_order_relaxed);
    if (cur != 0) {
        return;
    }
    bool enabled = (::isatty(STDERR_FILENO) != 0)
                && (std::getenv("NO_COLOR") == nullptr)
                && (std::getenv("CLICOLOR") == nullptr
                       || std::strcmp(std::getenv("CLICOLOR"), "0") != 0);
    g_color_state.store(enabled ? 1 : -1, std::memory_order_relaxed);
}

void force_color_on_for_tests() noexcept {
    g_color_state.store(1, std::memory_order_relaxed);
}

}  // namespace lock

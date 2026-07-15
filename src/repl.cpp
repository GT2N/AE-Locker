// lock::repl — GNU readline + Tab completion bridge for the `lock --cli` REPL.
//
// All direct linkage against libreadline (and its typical companion libtinfo)
// lives here. cli.cpp calls the two entry points declared in repl.hpp and
// never includes readline.h itself.
//
// Completion strategy:
//   * First token (start==0): offer REPL-internal commands (help/?/h/quit/exit/q)
//     plus the three real subcommands (encrypt/decrypt/list).
//   * Token immediately after a help/?/h command: offer the help topic list
//     (encrypt/decrypt/list).
//   * `--xxx` token after a subcommand: offer the long-flag set that applies
//     to that subcommand (encrypt extras: --compress/--fast/--level/--auto/
//     --max-depth/--chunk-size; decrypt: --auto/--max-depth; list: none).
//   * `--compress <TAB>`: none/lz4/zstd.
//   * `--lang <TAB>`: en/zh.
//   * Everything else: return nullptr so readline falls back to its built-in
//     filename completion (rl_filename_completion_function).
#include <lock/repl.hpp>

#if LOCK_HAVE_READLINE
#include <lock/i18n.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

extern "C" {
#include <readline/history.h>
#include <readline/readline.h>
}

namespace lock {
namespace {

// ---- Static candidate tables ----------------------------------------------

// First-token candidates emitted unconditionally (REPL-internal commands
// plus the three real subcommands). Ordering mostly mirrors how the README
// lists commands; the generator performs a substring filter so order is
// purely cosmetic, but a stable order keeps test logs diff-friendly.
constexpr std::string_view kFirstTokenCandidates[] = {
    "encrypt", "decrypt", "list",
    "help", "?", "h",
    "quit", "exit", "q",
};

// Help-topic candidates (used after `help`, `?`, or `h`).
constexpr std::string_view kHelpTopics[] = {
    "encrypt", "decrypt", "list",
};

// --compress value candidates.
constexpr std::string_view kCompressAlgos[] = {"none", "lz4", "zstd"};
// --lang value candidates.
constexpr std::string_view kLangs[] = {"en", "zh"};
// Short flag candidates emitted alongside the long ones for subcommands.
constexpr std::string_view kCommonShortFlags[] = {
    "-p", "-j", "-o", "-h", "-v", "-q", "-z", "-pev",
};

// Long flags common to encrypt / decrypt.
constexpr std::string_view kCommonLongFlags[] = {
    "--password-file", "--password-env-var", "--no-safe",
    "--jobs", "--output-dir", "--verbose", "--quiet",
    "--lang", "--no-color", "--help",
};

// Long flags exclusive to encrypt.
constexpr std::string_view kEncryptOnlyLongFlags[] = {
    "--chunk-size", "--compress", "--fast", "--level",
    "--auto", "--max-depth",
};

// Long flags that decrypt also accepts (in addition to common ones).
constexpr std::string_view kDecryptExtraLongFlags[] = {
    "--auto", "--max-depth",
};

// ---- Small accessor -------------------------------------------------------

const std::vector<std::string_view>& common_long_flags() {
    static const std::vector<std::string_view> v(
        std::begin(kCommonLongFlags), std::end(kCommonLongFlags));
    return v;
}
const std::vector<std::string_view>& encrypt_only_long_flags() {
    static const std::vector<std::string_view> v(
        std::begin(kEncryptOnlyLongFlags), std::end(kEncryptOnlyLongFlags));
    return v;
}
const std::vector<std::string_view>& decrypt_extra_long_flags() {
    static const std::vector<std::string_view> v(
        std::begin(kDecryptExtraLongFlags), std::end(kDecryptExtraLongFlags));
    return v;
}
const std::vector<std::string_view>& common_short_flags() {
    static const std::vector<std::string_view> v(
        std::begin(kCommonShortFlags), std::end(kCommonShortFlags));
    return v;
}
const std::vector<std::string_view>& first_token_candidates() {
    static const std::vector<std::string_view> v(
        std::begin(kFirstTokenCandidates), std::end(kFirstTokenCandidates));
    return v;
}
const std::vector<std::string_view>& help_topics() {
    static const std::vector<std::string_view> v(
        std::begin(kHelpTopics), std::end(kHelpTopics));
    return v;
}
const std::vector<std::string_view>& compress_algos() {
    static const std::vector<std::string_view> v(
        std::begin(kCompressAlgos), std::end(kCompressAlgos));
    return v;
}
const std::vector<std::string_view>& langs() {
    static const std::vector<std::string_view> v(
        std::begin(kLangs), std::end(kLangs));
    return v;
}

// ---- readline RT helpers --------------------------------------------------

// readline writes through a `char*`; rl_line_buffer is a NUL-terminated C
// string. We slice tokens on whitespace so the completer can decide which
// enum of candidates applies to the current token.
//
// Returns the token immediately preceding the cursor (i.e. the token
// `rl_point` is currently editing), expressed as a 0-based offset into
// the buffer plus its length. `prev_word` is the word before that, used to
// detect `help <TAB>`, `encrypt --compress <TAB>`, etc.
struct TokenSlice {
    std::string buf;
    std::string cur;   // word being typed (the one Tab is completing)
    std::string prev;  // word immediately preceding `cur`
    int cur_start;     // 0-based index into buf where `cur` starts
};

TokenSlice slice_line() {
    // Walk `rl_line_buffer` up to `rl_point` and split into [cur] (the
    // word the cursor is editing) plus [prev] (the word immediately
    // preceding it). When the cursor sits AT or AFTER a whitespace char
    // (the user just typed a space) `cur` is empty and `prev` is the
    // last token to the left — this is exactly what readline expects so
    // `encrypt --compress <TAB>` correctly enters the enum value slot.
    TokenSlice s;
    const char* p = rl_line_buffer;
    if (p == nullptr) {
        return s;
    }
    const int pt = rl_point;
    s.buf.assign(p, static_cast<size_t>(pt));
    size_t i = s.buf.size();

    const bool cursor_in_whitespace =
        (i == 0) ||
        std::isspace(static_cast<unsigned char>(s.buf[i - 1]));

    if (cursor_in_whitespace) {
        s.cur.clear();
        s.cur_start = static_cast<int>(i);
        while (i > 0 && std::isspace(static_cast<unsigned char>(s.buf[i - 1]))) {
            --i;
        }
        size_t prev_end = i;
        while (i > 0 && !std::isspace(static_cast<unsigned char>(s.buf[i - 1]))) {
            --i;
        }
        s.prev.assign(s.buf, i, prev_end - i);
        return s;
    }

    size_t cur_end = i;
    while (i > 0 && !std::isspace(static_cast<unsigned char>(s.buf[i - 1]))) {
        --i;
    }
    s.cur.assign(s.buf, i, cur_end - i);
    s.cur_start = static_cast<int>(i);
    size_t j = i;
    while (j > 0 && std::isspace(static_cast<unsigned char>(s.buf[j - 1]))) {
        --j;
    }
    size_t prev_end = j;
    while (j > 0 && !std::isspace(static_cast<unsigned char>(s.buf[j - 1]))) {
        --j;
    }
    s.prev.assign(s.buf, j, prev_end - j);
    return s;
}

// Trim a `--xxx=value` form down to `--xxx` so the long-flag candidate set
// can filter on the bare flag name. Returns the input unchanged if it does
// not contain `=`.
std::string flag_basename(std::string_view tok) {
    auto eq = tok.find('=');
    if (eq == std::string_view::npos) {
        return std::string(tok);
    }
    return std::string(tok.substr(0, eq));
}

// Decide which candidate vector applies to the cursor position. Returns
// nullptr to indicate "let readline do filename completion".
const std::vector<std::string_view>* candidate_vector(const TokenSlice& s) {
    if (s.cur_start == 0) {
        // The cursor is at the very first token. Offer the union of REPL
        // commands + subcommands regardless of whatever else the user has
        // typed.
        return &first_token_candidates();
    }
    // `help` / `?` / `h` followed by a token -> help topics.
    if (s.prev == "help" || s.prev == "?" || s.prev == "h") {
        return &help_topics();
    }
    // Subcommand already given: switch to flag completion.
    const std::string_view cmd = s.prev;
    const bool has_double_dash =
        !s.cur.empty() && s.cur.starts_with("--");
    if (s.cur.starts_with("-")) {
        // Combine common long & short flags plus the subcommand's extras.
        static thread_local std::vector<std::string_view> merged;
        merged.clear();
        auto push_view = [](const std::vector<std::string_view>& src) {
            for (auto sv : src) {
                merged.push_back(sv);
            }
        };
        if (has_double_dash) {
            push_view(common_long_flags());
            if (cmd == "encrypt") {
                push_view(encrypt_only_long_flags());
            } else if (cmd == "decrypt") {
                push_view(decrypt_extra_long_flags());
            }
            // list only gets the common long flags.
        } else {
            push_view(common_short_flags());
            push_view(common_long_flags());
            if (cmd == "encrypt") {
                push_view(encrypt_only_long_flags());
            } else if (cmd == "decrypt") {
                push_view(decrypt_extra_long_flags());
            }
        }
        return &merged;
    }
    // Argument slot of an option that takes a known enum value.
    if (s.prev == "--compress") {
        return &compress_algos();
    }
    if (s.prev == "--lang") {
        return &langs();
    }
    // Bare positional after a subcommand or anything else -> allow
    // filename completion.
    return nullptr;
}

// ---- readline generator function ------------------------------------------

// readline's protocol: keep state in a `static` iterator; on the first
// invocation (state==0) reset and prime the candidate list, then on
// subsequent invocations (state>0) walk forward returning one
// NUL-terminated match at a time. Returns nullptr when exhausted.
//
// `text` is the prefix readline extracted from rl_line_buffer for us. We
// derive the prefix ourselves (from the position the completer called us
// for) and therefore do not consume `text` here; the parameter is left
// unnamed so that -Wunused-parameter stays quiet under our strict flags.
char* lock_generator(const char* /*text*/, int state) {
    static thread_local std::vector<std::string> matches;
    static thread_local size_t idx = 0;

    if (state == 0) {
        matches.clear();
        idx = 0;
        TokenSlice s = slice_line();
        const std::vector<std::string_view>* v = candidate_vector(s);
        std::string_view needle = s.cur;
        // Strip `--xxx=value` down to `--xxx` so the long-flag candidate
        // set still filters on the bare name.
        std::string bare = flag_basename(needle);
        if (v != nullptr) {
            // If the user typed `--`, exclude short `-X` flags; if they typed
            // a single-dash short, exclude `--` long flags. Empty needle means
            // list everything.
            const bool want_long = needle.starts_with("--");
            const bool want_short = !needle.empty()
                                 && needle.starts_with("-")
                                 && !want_long;
            for (std::string_view cand : *v) {
                if (!bare.empty()
                    && (cand.size() < bare.size()
                        || cand.compare(0, bare.size(), bare) != 0)) {
                    continue;
                }
                if (want_long && !cand.starts_with("--")) {
                    continue;
                }
                if (want_short && cand.starts_with("--")) {
                    continue;
                }
                matches.emplace_back(cand);
            }
        }
    }

    if (idx >= matches.size()) {
        return nullptr;
    }
    const std::string& m = matches[idx++];
    // readline takes ownership of the returned `char*` and frees the last
    // one via `free` when it is no longer needed. Duplicate via malloc so the
    // ownership transfer is well-defined.
    char* owned = static_cast<char*>(std::malloc(m.size() + 1U));
    if (owned == nullptr) {
        return nullptr;
    }
    std::memcpy(owned, m.data(), m.size());
    owned[m.size()] = '\0';
    return owned;
}

// ---- readline completion function -----------------------------------------

// Returning nullptr from this function makes readline keep going with its
// DEFAULT completion (filename). When we want to take over we return the
// array produced by rl_completion_matches(text, lock_generator). The
// readline C API exacts `char** (*)(const char*, int, int)` here; our
// `lock_generator` already matches `rl_compentry_func_t = char*(*)(const char*, int)`
// so the only cast required is the no-op insertion back into
// `rl_attempted_completion_function` near the bottom.
char** lock_completion(const char* text, int /*start*/, int /*end*/) {
    TokenSlice s = slice_line();
    const std::vector<std::string_view>* v = candidate_vector(s);

    // If the only thing we could offer is filename completion (v == nullptr)
    // OR we did not match any of our candidate slots, fall back to
    // readline's default filename completion.
    if (v == nullptr) {
        return nullptr;
    }
    // Tell readline to append a plain space after our matches — our
    // candidates are words (commands / flags / values), not filenames, so
    // the path-separator default would be misleading.
    rl_completion_append_character = ' ';
    // Suppress the default filename fallback so `--` will not pick up a
    // bogus file completion mixed into our candidate set.
    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, lock_generator);
}

}  // namespace

bool repl_readline(std::string prompt, std::string& out) {
    char* raw = ::readline(prompt.c_str());
    if (raw == nullptr) {
        // EOF (Ctrl-D on an empty prompt).
        return false;
    }
    std::string line(raw);
    std::free(raw);
    // Record non-blank lines into the per-process history. Iterate on `char`
    // (std::string::const_iterator value type) and widen explicitly via
    // `static_cast<unsigned char>` for std::isspace so the conversion is
    // signedness-clean against -Wconversion.
    bool blank = true;
    for (char c : line) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            blank = false;
            break;
        }
    }
    if (!blank) {
        ::add_history(line.c_str());
    }
    out = std::move(line);
    return true;
}

void repl_install_completer() noexcept {
    static thread_local bool installed = false;
    if (installed) {
        return;
    }
    installed = true;
    rl_attempted_completion_function = lock_completion;
    // Tell readline not to complete on the tab character alone (so the user
    // can see all candidates when the prefix is empty, like bash).
    rl_completion_query_items = 0;  // never ask before listing many entries
}

}  // namespace lock

#else  // !LOCK_HAVE_READLINE

// Without libreadline the whole module degenerates to two trivial stubs that
// never get called (cli.cpp guards the calls with #if LOCK_HAVE_READLINE).
// They exist purely so the symbol exists for the linker when something ever
// evolves to call them unconditionally.
namespace lock {

bool repl_readline(std::string /*prompt*/, std::string& out) {
    out.clear();
    return false;
}

void repl_install_completer() noexcept {
}

}  // namespace lock

#endif  // LOCK_HAVE_READLINE

// ae_locker::i18n — minimal table-driven internationalisation (en / zh) plus
// ANSI-colour helpers for stderr diagnostics.  No gettext / ICU dependency;
// the look-up is a single array index into a per-language const char* table.
//
// Usage:
//   ae_locker::I18n::init(Lang::En);            // set at startup (cli_main)
//   std::cerr << ae_locker::color_error(ae_locker::tr(Str::Err_output_exists));
//   if (ae_locker::current() == Lang::Zh) { ... }
//
// Colour policy:
//   - enable_color_if_tty() probes isatty(STDERR_FILENO) + NO_COLOR +
//     CLICOLOR and sets an internal atomic flag.  Called once at cli_main
//     entry.  disable_color() (the --no-color flag) forces the flag off
//     regardless of the tty probe.  When the flag is off every color_*
//     helper returns its input verbatim (no escape codes).
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ae_locker {

// ---------------------------------------------------------------------------
// Language tag.
// ---------------------------------------------------------------------------
enum class Lang : uint8_t { En, Zh };

// ---------------------------------------------------------------------------
// String-table keys.  A single enum spans every user-facing message in the
// project.  The id is grouped by module via a prefix convention in the id
// name (Help_*, Err_*, Warn_*, Prompt_*, List_*, Progress_*, Common_*) so
// the source stays readable; the underlying integral order is what the
// table lookup in src/i18n.cpp relies on.
//
// IMPORTANT: when you add a new id you MUST also add the matching entries
// to BOTH `en_strings` and `zh_strings` in src/i18n.cpp, at the same
// index.  A static_assert in i18n.cpp cross-checks the array length
// against the sentinel value below.
// ---------------------------------------------------------------------------
enum class Str : uint16_t {
    // ---- Help / usage ------------------------------------------------------
    Help_usage_line,            // "lock 1.0.0 — AES-256-CTR + HMAC-SHA256 file encryption"
    Help_usage_desc,            // one-liner description
    Help_usage_cmd,             // "Usage:" + variants
    Help_cmd_encrypt,
    Help_cmd_decrypt,
    Help_cmd_list,
    Help_grp_common,            // "Common Options:" header
    Help_grp_encrypt,           // "Encrypt-only Options:" header
    Help_grp_decrypt,           // "Decrypt-only Options:" header
    Help_grp_examples,          // "Examples:" header
    Help_opt_password_file,
    Help_opt_password_env,
    Help_opt_no_safe,
    Help_opt_jobs,
    Help_opt_output_dir,
    Help_opt_chunk_size,
    Help_opt_compress,
    Help_opt_compress_z,
    Help_opt_compress_fast,
    Help_opt_level,
    Help_opt_auto,
    Help_opt_max_depth,
    Help_opt_verbose,
    Help_opt_quiet,
    Help_opt_lang,
    Help_opt_no_color,
    Help_opt_version,
    Help_opt_help,
    Help_example_1,             // example lines with # comment
    Help_example_2,
    Help_example_3,
    Help_example_4,
    Help_decrypt_note,          // "decrypt also supports --auto / --max-depth..." note
    Help_per_subcmd_hint,       // one-liner appended to general help: "Run `lock <cmd> --help` ..."
    Help_subcmd_encrypt_intro,  // 1-2 line intro for `lock encrypt --help`
    Help_subcmd_decrypt_intro,  // analog, decrypt
    Help_subcmd_list_intro,     // analog, list
    Help_subcmd_encrypt_examples, // examples block tailored for `lock encrypt --help`
    Help_subcmd_decrypt_examples, // analog, decrypt
    Help_subcmd_list_examples,    // analog, list

    // ---- Common error / status labels --------------------------------------
    Err_label,                  // "error: "
    Warn_label,                 // "warning: "
    Err_unknown_cmd,            // "unknown command 'X'"
    Err_arg_value_required,     // "flag X requires a value"
    Err_arg_requires_int,       // "flag X requires an integer value"
    Err_arg_requires_nonneg,    // "flag X requires a non-negative integer"
    Err_arg_out_of_range,       // "flag X value out of range [..]"
    Err_arg_invalid_compress,   // "invalid --compress value 'X'"
    Err_arg_unknown,            // "unknown flag 'X'"
    Err_arg_requires_command,   // "-c requires a command"
    Err_no_input_files,         // "no input files specified"
    Err_chunk_size_min,         // "--chunk-size must be at least 4096"
    Err_chunk_size_mod,         // "--chunk-size must be a multiple of 16"
    Err_auto_repeat,            // "--auto specified more than once"
    Err_auto_with_list,         // "--auto is not supported by the 'list' command"
    Err_auto_with_positional,   // "--auto <dir> is exclusive with positional file arguments"
    Err_auto_no_dir,            // "--auto dir 'X' does not exist or is not a directory"
    Err_auto_no_output,         // "--auto requires explicit -o/--output-dir"
    Err_max_depth_no_auto,      // "--max-depth requires --auto"
    Err_max_depth_range,        // "--max-depth must be >= -1 (-1 means unlimited)"
    Err_level_range,            // "--level value out of range [1, 22]"
    Err_lang_invalid,           // "invalid --lang value 'X' (must be en or zh)"
    Err_output_exists,          // "'X' already exists. Remove it or choose a different output directory."
    Err_output_dir_create,      // "output directory 'X' cannot be created: MSG"
    Err_scan_auto_dir,          // "failed to scan --auto dir 'X'"
    Err_no_eligible_files,      // "no eligible files found under 'X'"
    Err_not_locked,             // "'X' is not a .locked file (bad magic)"
    Err_first_error,            // prefix when re-throwing per-file error from a worker
    Err_repl_unknown_help_topic, // REPL-only "unknown help topic '%s' (choose: encrypt|decrypt|list)"

    // ---- Crypto / IO classification error messages (wrappers) ------------
    // Substrings used to classify untyped std::runtime_error from the lower
    // crypto / container / kdf modules into ExitCode buckets; also surfaced
    // directly to the user.
    Err_HMAC_generic,           // "HMAC verification failed"
    Err_GCM_auth,                // "GCM authentication failed"
    Err_scrypt_failed,          // "scrypt failed"
    Err_RAND_short,             // "RAND_bytes returned short buffer"
    Err_input_missing,          // "input file 'X' does not exist / cannot open"
    Err_io_generic,             // generic IO suffix used mid-message

    // ---- Password / safe --------------------------------------------------
    Prompt_enter,               // EN: "Enter password (input hidden): "  ZH: "请输入密码(输入不可见): "
    Prompt_confirm,             // EN: "Confirm password: "  ZH: "请再次输入以确认: "
    Prompt_password_mismatch,   // "passwords do not match" / "两次输入的密码不一致"
    Prompt_password_empty,       // "password cannot be empty" / "密码不能为空"
    Warn_password_unsafe_file,   // "Reading password from a file is considered unsafe..."
    Warn_password_unsafe_env,    // "Reading password from an environment variable is considered unsafe..."
    Warn_unsafe_file_short,      // "password read from file — ensure the file is not logged"
    Warn_unsafe_env_short,       // "password read from environment variable 'X' — env vars may leak..."
    Err_pw_open,                // "cannot open password file: X"
    Err_pw_empty_file,          // "password file is empty: X"
    Err_pw_too_long,            // "password file exceeds 4 KiB limit"
    Err_pw_exceeds_max,         // "password exceeds maximum length"
    Err_pw_env_unset,           // "environment variable 'X' is not set"
    Err_pw_env_empty,           // "environment variable 'X' is empty"
    Err_pw_read_failed,         // "read() from tty failed"
    Err_pw_invalid_mode,        // "invalid password mode"
    Err_pw_tty_open,            // "cannot open /dev/tty — interactive password unavailable (stdin redirected?)"
    Err_term_getattr,           // "tcgetattr failed on tty"
    Err_term_setattr,           // "tcsetattr failed disabling echo"

    // ---- Progress bar labels ----------------------------------------------
    Progress_overall_prefix,    // "Overall: "
    Progress_file_label_enc,    // EN: "Encrypting " ZH: "加密中 " (prepended to file name prefix)
    Progress_file_label_dec,    // EN: "Decrypting " ZH: "解密中 "
    Progress_done,             // EN: "done"  ZH: "完成"
    Progress_pending,          // "[pending] "

    // ---- `list` command field labels --------------------------------------
    List_file_header,          // "File: X"
    List_not_locked,           // "(not a .locked file)"
    List_field_magic,
    List_field_version,
    List_field_algorithm,
    List_field_kdf,
    List_field_salt,
    List_field_base_iv,
    List_field_original_size,
    List_field_chunk_size,
    List_field_chunk_count,
    List_field_compression,
    List_field_stored_size,
    List_field_filename_len,
    List_field_data_offset,
    List_field_file_size,
    List_field_overhead,
    List_field_error,          // "  error: X"

    // ---- Verbose / status -------------------------------------------------
    Verbose_lang_detected,     // "[lang] detected=X effective=Y (env: VAR=VALUE or unset)"
    Verbose_memory_line,       // "[memory] available=.. MiB; chunk_size=.. KiB; jobs=.. ...."

    // ---- Version + interactive REPL ---------------------------------------
    Version_line,             // "lock 1.0.0"
    Repl_banner,               // "lock interactive mode"
    Repl_prompt,               // "> "
    Repl_commands_hint,        // "Commands: encrypt, decrypt, list, quit"
    Repl_unknown_command_pre,  // "unknown command '"     (prefix)
    Repl_unknown_command_suf_en, // "' — try 'encrypt', 'decrypt', 'list', or 'quit'\n"
    Repl_unknown_command_suf_zh, // "'——请使用 'encrypt'、'decrypt'、'list' 或 'quit'\n"
    Repl_file_prompt,          // "  file path (empty line to finish): "
    Repl_no_files,            // "  no files specified — aborted"
    Repl_help_hint,           // one-time hint printed at REPL startup: "Enter `help` for command help, `quit` to exit"

    // ---- Completion script generation ----
    Err_completion_missing,     // "missing shell argument (use: bash|zsh|fish)"
    Err_completion_unsupported, // "unsupported shell '%s' (choose: bash, zsh, fish)"

    // ---- REPL readline ----
    // Verbose/status emitted by the readline-backed REPL. Kept in a dedicated
    // sub-block so concurrent waves do not collide on adjacent Str ids.
    Repl_readline_missing,      // verbose: emitted once at REPL startup when libreadline was not linked

    // ---- TUI ----
    // Strings used by the ftxui-based TUI (src/tui.cpp). Wave A only needs the
    // main-menu labels + a placeholder for not-yet-implemented submenus.
    Err_tui_not_a_tty,          // "TUI mode requires an interactive terminal (tty)"
    Err_tui_no_color,           // "TUI mode requires colour support (don't use --no-color or NO_COLOR)"
    Tui_menu_title,             // "lock TUI Main Menu"
    Tui_menu_encrypt,           // "Encrypt"
    Tui_menu_decrypt,           // "Decrypt"
    Tui_menu_list,              // "List"
    Tui_menu_quit,              // "Quit"
    Tui_not_implemented_yet,    // "(This submenu is not implemented yet)"
    Tui_press_enter_to_return,  // "Press Enter to return to main menu"

    // ---- TUI (forms) ----
    // Wave B: per-subcommand submenus (Encrypt form / Decrypt form /
    // List not-available).  Keep the sub-block contiguous so concurrent
    // waves do not collide on adjacent Str ids.
    Tui_encrypt_form_title,       // "Encrypt — fill in the fields then Confirm"
    Tui_decrypt_form_title,       // "Decrypt — fill in the fields then Confirm"
    Tui_field_files,              // "Files (one path per line, empty line to finish)"
    Tui_field_add_file,           // "Add file (empty to finish adding)"
    Tui_field_output_dir,         // "Output directory (empty = default)"
    Tui_field_compression,        // "Compression"
    Tui_compress_none,            // "none"
    Tui_compress_lz4,             // "lz4 (fast)"
    Tui_compress_zstd,            // "zstd (balanced)"
    Tui_field_level,              // "Compression level (1..22, zstd only; ignored otherwise)"
    Tui_field_jobs,               // "Jobs (0 = auto-recommend)"
    Tui_btn_confirm,              // "Confirm"
    Tui_btn_cancel,               // "Cancel"
    Tui_password_first,          // "Password (hidden)"
    Tui_password_second,         // "Confirm password (hidden)"
    Tui_password_mismatch,       // "Passwords do not match — aborting"
    Tui_password_empty,           // "Password cannot be empty"
    Tui_no_files_error,           // "No files specified"
    Tui_level_range_error,        // "Compression level must be 1..22"
    Tui_result_ok,                // "Operation finished successfully (rc=0)"
    Tui_result_err,               // "Operation failed"
    Tui_press_enter_to_continue, // "Press Enter to continue"
    Tui_list_not_available_title, // "List — not available in TUI mode"
    Tui_list_not_available_body,  // "The `list` subcommand writes to stdout, which conflicts
                                   // with the full-screen TUI. Exit the TUI and run
                                   // `lock list <file>` from the shell instead."

    // ---- TUI (wizard) ----
    // Wave D: multi-step wizard framework + file browser + real List
    // submenu. Keep the sub-block contiguous so concurrent waves do not
    // collide on adjacent Str ids. Existing forms-block ids are reused
    // where the wording is identical (e.g. Tui_password_empty /
    // Tui_password_mismatch / Tui_no_files_error / Tui_field_* /
    // Tui_compress_* / Tui_btn_cancel).
    Tui_wizard_step_prefix,         // "Step " / "步骤 "
    Tui_wizard_step_of,             // "/" / "/"
    Tui_step_select_files,          // "Select files" / "选择文件"
    Tui_step_compress_opts,         // "Compression" / "压缩参数"
    Tui_step_output_concurrency,   // "Output & concurrency" / "输出与并发"
    Tui_step_password,              // "Password" / "密码"
    Tui_step_select_locked,        // "Select .locked file(s)" / "选择 .locked 文件"
    Tui_btn_back,                  // "← Back" / "← 上一步"
    Tui_btn_next,                  // "Next →" / "下一步 →"
    Tui_btn_done,                  // "Finish" / "完成"
    Tui_err_select_at_least_one_file, // "Please select at least one file" / "请至少选择一个文件"
    Tui_file_browser_title,        // "File browser — Space to select file, Enter to open directory"
    Tui_file_browser_current_path, // "Current path" / "当前路径"
    Tui_file_browser_selected,     // "Selected" / "已选"
    Tui_file_browser_unreadable,   // "Cannot read this directory" / "无法读取此目录"
    Tui_list_select_files,         // "Select .locked file(s) to view" / "选择要查看的 .locked 文件"
    Tui_list_view_btn,             // "View" / "查看"
    Tui_press_enter_after_op,      // "Operation done. Press Enter to return to main menu"
                                    //   / "操作完成。按回车返回主菜单"

    Str_sentinel              // MUST be last — used to size the string table
};

// ---------------------------------------------------------------------------
// I18n controller.
// ---------------------------------------------------------------------------
struct I18n final {
    // Set the active language.  Idempotent; safe to call multiple times.
    static void init(Lang lang) noexcept;

    // Active language.
    [[nodiscard]] static Lang current() noexcept;

    // Look up a string.  Returns a hard-coded "(missing string)" fallback
    // if `s` is out of range (programming error, not user-facing).
    [[nodiscard]] static const char* get(Str s) noexcept;
};

// Convenience alias — most call sites want `tr(Str::Err_output_exists)`.
[[nodiscard]] inline const char* tr(Str s) noexcept { return I18n::get(s); }

// Substitute the first `%s` placeholder in `tmpl` with `a`.
[[nodiscard]] std::string subst(std::string_view tmpl, std::string_view a);

// Substitute the first two `%s` placeholders in `tmpl` with `a` then `b`.
[[nodiscard]] std::string subst2(std::string_view tmpl,
                                 std::string_view a,
                                 std::string_view b);

// Substitute the first three `%s` placeholders in `tmpl` with `a`, `b`, `c`.
[[nodiscard]] std::string subst3(std::string_view tmpl,
                                 std::string_view a,
                                 std::string_view b,
                                 std::string_view c);

// Detect the user's preferred language from the environment.
// Probe order: $LC_ALL → $LC_MESSAGES → $LANG.  The first non-empty value
// wins; if it starts with "zh" (case-insensitive) the result is Lang::Zh;
// anything else (including "C" / "POSIX" / unset) falls back to Lang::En.
[[nodiscard]] Lang detect_lang_from_env() noexcept;

// Probe which environment variable supplied the detected language, returned
// alongside a copy of the value (or "unset").  Used by the -v verbose line
// so the user can see exactly what got picked up.
struct EnvLangSource {
    const char* var_name;          // "LC_ALL" / "LC_MESSAGES" / "LANG" / ""
    std::string value;             // "" if unset (caller prints "unset")
    Lang        detected;
};
[[nodiscard]] EnvLangSource probe_env_lang_source() noexcept;

// ---------------------------------------------------------------------------
// Colour helpers (ANSI SGR codes embedded in the returned std::string).
// When colour is disabled each helper returns its input verbatim.
// ---------------------------------------------------------------------------
[[nodiscard]] std::string color_error(std::string_view text);   // red   \x1b[31m
[[nodiscard]] std::string color_warn(std::string_view text);   // yellow \x1b[33m
[[nodiscard]] std::string color_ok(std::string_view text);     // green  \x1b[32m
[[nodiscard]] std::string color_path(std::string_view text);   // cyan  \x1b[36m — file/path highlight
[[nodiscard]] std::string color_none(std::string_view text);   // passthrough (no SGR codes)

// Force colour OFF (called by --no-color).  Overrides enable_color_if_tty.
void disable_color() noexcept;

// Query the current colour-enabled state. Returns false after disable_color()
// or when enable_color_if_tty() determined the terminal is non-tty.
[[nodiscard]] bool color_enabled() noexcept;

// Auto-detect colour support: enable iff isatty(STDERR_FILENO) AND
// getenv("NO_COLOR") is null AND getenv("CLICOLOR") is not "0".
// Should be called once at cli_main entry, BEFORE any colour helpers run.
void enable_color_if_tty() noexcept;

// Test hook: explicitly enable colour regardless of tty (used by sanity
// scripts that pipe stderr to a captured file).
void force_color_on_for_tests() noexcept;

}  // namespace ae_locker

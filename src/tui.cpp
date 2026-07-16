// lock::tui — ftxui-driven menu UI.
//
// Wave D replaces Wave B's single-screen forms with multi-step wizards:
//   - Encrypt: 4 steps — files / compression / output+concurrency / password.
//   - Decrypt: 3 steps — files / output+concurrency / password.
//   - List:    real file browser + view button; replaces Wave B's
//              "not available" placeholder.
//
// Wizard flow:
//   1. User picks Encrypt/Decrypt/List from the main menu.
//   2. The corresponding wizard runs in its own ScreenInteractive — each step
//      is one screen, with a `[1/4]→[2/4]→…` step-progress indicator and the
//      overall step title.  Back/Next/Navigate buttons drive transitions; the
//      per-step `validate_step(i)` callback gates Next/Finish.
//   3. On Finish, the wizard's screen.Exit() returns Disposition::Run{Encrypt,
//      Decrypt,List}; next_screen_postop runs run_encrypt/run_decrypt/run_list
//      in the plain (non-alt-screen) terminal so stdout/stderr/progress reach
//      the user directly; afterwards an Enter-to-continue prompt is shown.
//   4. The TUI then loops back to the main menu so the user can start another
//      operation without re-running `lock --tui`.
//
// Cancel/Esc inside any wizard returns to the main menu (not re-execute).
// Quit from the main menu exits with ExitCode::Ok.
//
// Wave A's stdin/stderr tty + colour guards inside run_tui() are preserved
// untouched.
#include <lock/tui.hpp>

#include <lock/cli_dispatch.hpp>
#include <lock/i18n.hpp>

#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace lock::tui {

namespace {

bool stdin_is_tty() noexcept {
    return ::isatty(STDIN_FILENO) != 0;
}

bool stderr_is_tty() noexcept {
    return ::isatty(STDERR_FILENO) != 0;
}

// ---------------------------------------------------------------------------
// What the top-level menu loop should do next after `screen.Exit()`.
// ---------------------------------------------------------------------------
enum class Disposition {
    Quit,         // (kept for legacy callers; only Quit())
    RunEncrypt,   // execute the captured encrypt form
    RunDecrypt,   // execute the captured decrypt form
    RunList,      // execute run_list with selected .locked files
    Cancelled,    // user pressed Cancel/Esc; return to main menu
};

// ---------------------------------------------------------------------------
// Form state — a single struct per submenu.  Lives outside the screen so it
// survives `screen.Exit()` and is read by the orchestrator afterward.
// ---------------------------------------------------------------------------
struct EncryptForm {
    std::string file_entry;
    std::vector<std::string> files;
    std::string output_dir;
    int compression = 0;
    std::string level;
    std::string jobs;
    std::string password;
    std::string password_confirm;
};

struct DecryptForm {
    std::string file_entry;
    std::vector<std::string> files;
    std::string output_dir;
    std::string jobs;
    std::string password;
};

// File-browser state shared by Encrypt/Decrypt/List pickers.  The browser
// component holds a live `st`-by-reference capture so chdir/selection state
// persists across renders; the orchestrator reads `st.selected` (absolute
// paths) when the wizard is closed.
struct BrowserEntry {
    std::filesystem::path path;
    std::string display;
    bool is_dir : 1;
    bool is_up : 1;   // ".." navigation entry.
    BrowserEntry() : is_dir(false), is_up(false) {}
};

struct FileBrowserState {
    std::filesystem::path cwd;
    std::vector<std::string> selected;  // selected absolute file paths.
    std::string unreadable;              // last error message; empty if OK.
    bool only_dot_locked = false;        // encrypt=false; decrypt/list=true.
};

// Read-only flag returned from `run_wizard` so the caller can highlight
// which step last failed validation. -1 = no error.
struct WizardOutcome {
    Disposition d = Disposition::Cancelled;
    int error_step = -1;
};

// Render a labelled component so each form row reads "*Label:*  [field]".
ftxui::Component label_field(std::string label, ftxui::Component field) {
    return ftxui::Renderer(field, [label, field] {
        return ftxui::hbox({
            ftxui::text(label) | ftxui::bold | ftxui::size(ftxui::WIDTH,
                                                            ftxui::EQUAL, 28),
            ftxui::separator(),
            field->Render() | ftxui::flex,
        });
    });
}

// ---------------------------------------------------------------------------
// Map the radiobox index to the public CompressionId.
// ---------------------------------------------------------------------------
CompressionId index_to_compression(int idx) {
    switch (idx) {
        case 1:  return CompressionId::LZ4;
        case 2:  return CompressionId::ZSTD;
        default: return CompressionId::NONE;
    }
}

// `jobs` text → uint32_t (non-numeric/empty falls back to 0 = auto).
uint32_t parse_jobs(const std::string& s) {
    if (s.empty()) return 0;
    char* endp = nullptr;
    long v = std::strtol(s.c_str(), &endp, 10);
    if (endp == s.c_str() || *endp != '\0' || v < 0) return 0;
    if (v > static_cast<long>(UINT32_MAX)) return UINT32_MAX;
    return static_cast<uint32_t>(v);
}

int parse_level(const std::string& s) {
    if (s.empty()) return 3;
    char* endp = nullptr;
    long v = std::strtol(s.c_str(), &endp, 10);
    if (endp == s.c_str() || *endp != '\0') return 3;
    if (v < 1) return 1;
    if (v > 22) return 22;
    return static_cast<int>(v);
}

// Scrub the throwaway password tmpfile: overwrite with zero bytes so the
// disk blocks don't retain the password past unlink (best-effort, matches
// the security note in README), then unlink.  `pw_len` is the byte count
// we previously wrote — we scrub at least that many bytes plus one.
void scrub_tmpfile(const char* path, size_t pw_len) {
    int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        std::string zeros(pw_len + 1, '\0');
        ::write(fd, zeros.data(), zeros.size());
        ::close(fd);
    }
    ::unlink(path);
}

// Print the post-operation result line to stderr.  Alt-screen has already
// exited by the caller, so plain fprintf reaches the user's terminal.
void emit_result(ExitCode rc) {
    if (rc == ExitCode::Ok) {
        std::fprintf(stderr, "%s%s\n",
                     color_ok("").c_str(),
                     tr(Str::Tui_result_ok));
    } else {
        std::fprintf(stderr, "%s%s (rc=%d)\n",
                     color_error(tr(Str::Err_label)).c_str(),
                     tr(Str::Tui_result_err),
                     static_cast<int>(rc));
    }
}

// ---------------------------------------------------------------------------
// Execute the captured Encrypt / Decrypt forms in the plain terminal
// (alt-screen already exited by the caller).  Mirrors run_interactive()'s
// error handling (cli.cpp) so the user sees a `error: <msg>` line and a
// exit-code summary line.
// ---------------------------------------------------------------------------
ExitCode execute_encrypt(const EncryptForm& f) {
    ProgressTracker tracker;
    EncryptCliArgs args;
    args.files             = f.files;
    args.password_mode    = PasswordMode::Interactive;
    // We already captured the password in the TUI form; running the
    // interactive safe.cpp path would re-prompt via termios, which is
    // incompatible with the just-exited alt-screen.  Hand the password over
    // via the FromFile route is out (security), so we instead inline the
    // KDF ourselves — but run_encrypt's first step is acquire_password()
    // which ALWAYS prompts through term.cpp's /dev/tty when mode=Interactive.
    //
    // Workaround: write the captured password into the bundle using the
    // non-interactive path (FromFile) with a throwaway tmpfile scrubbed with
    // fsync-on-unlink-by-overwrite at end.  `--no-safe` is required by the
    // CLI policy for non-interactive password sources; we satisfy it.
    char tmpl[] = "/tmp/lock_tui_pw_XXXXXX";
    int fd = ::mkstemp(tmpl);
    if (fd < 0) {
        std::fprintf(stderr, "%s%s\n",
                     color_error(tr(Str::Err_label)).c_str(),
                     "cannot create temp file for password handover");
        return ExitCode::Io;
    }
    ::write(fd, f.password.data(),
            static_cast<size_t>(f.password.size()));
    ::close(fd);
    args.password_mode = PasswordMode::FromFile;
    args.password_file  = tmpl;
    args.no_safe        = true;
    args.output_dir     = f.output_dir;
    args.compression     = index_to_compression(f.compression);
    args.compression_level = parse_level(f.level);
    args.jobs            = parse_jobs(f.jobs);
    args.jobs_explicit   = !f.jobs.empty() && f.jobs != "0";
    args.chunk_size      = static_cast<uint32_t>(DEFAULT_CHUNK_SIZE);
    args.quiet           = true;
    ExitCode rc = ExitCode::Internal;
    try {
        rc = run_encrypt(args, tracker);
    } catch (const LockError& e) {
        std::fprintf(stderr, "%s%s\n",
                     color_error(tr(Str::Err_label)).c_str(), e.what());
        rc = e.code();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s%s\n",
                     color_error(tr(Str::Err_label)).c_str(), e.what());
    }
    scrub_tmpfile(tmpl, f.password.size());
    emit_result(rc);
    return rc;
}

ExitCode execute_decrypt(const DecryptForm& f) {
    ProgressTracker tracker;
    DecryptCliArgs args;
    args.files          = f.files;
    char tmpl[] = "/tmp/lock_tui_pw_XXXXXX";
    int fd = ::mkstemp(tmpl);
    if (fd < 0) {
        std::fprintf(stderr, "%s%s\n",
                     color_error(tr(Str::Err_label)).c_str(),
                     "cannot create temp file for password handover");
        return ExitCode::Io;
    }
    ::write(fd, f.password.data(),
            static_cast<size_t>(f.password.size()));
    ::close(fd);
    args.password_mode = PasswordMode::FromFile;
    args.password_file  = tmpl;
    args.no_safe        = true;
    args.output_dir     = f.output_dir;
    args.jobs            = parse_jobs(f.jobs);
    args.jobs_explicit   = !f.jobs.empty() && f.jobs != "0";
    args.chunk_size      = static_cast<uint32_t>(DEFAULT_CHUNK_SIZE);
    args.quiet           = true;
    ExitCode rc = ExitCode::Internal;
    try {
        rc = run_decrypt(args, tracker);
    } catch (const LockError& e) {
        std::fprintf(stderr, "%s%s\n",
                     color_error(tr(Str::Err_label)).c_str(), e.what());
        rc = e.code();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s%s\n",
                     color_error(tr(Str::Err_label)).c_str(), e.what());
    }
    scrub_tmpfile(tmpl, f.password.size());
    emit_result(rc);
    return rc;
}


// ---------------------------------------------------------------------------
// File-browser primitive — used by step 0 of each wizard (and the List
// picker) to navigate the filesystem with arrow keys + Enter + Space.
// ---------------------------------------------------------------------------
// The browser keeps everything in shared_ptr-backed references because the
// ftxui Menu component binds `opt.selected` (the focused row index) by *raw
// pointer* into a live `int`.  The int must outlive the Menu component
// instance, and MenuBase will mutate it directly on every ArrowUp/Down
// event.  Stashing it in a shared_ptr lets us hand `&*selected` to Menu
// without worrying about it going out of scope when the
// show_encrypt_wizard / show_decrypt_wizard / show_list_picker stack
// frames yield to screen.Loop().
std::filesystem::path initial_browser_dir() {
    std::error_code ec;
    auto cwd = std::filesystem::current_path(ec);
    if (ec) {
        const char* home = std::getenv("HOME");
        if (home != nullptr && home[0] != '\0') {
            return std::filesystem::path{home};
        }
        return std::filesystem::path{"/"};
    }
    return cwd;
}

// Read the directory listing of `st.cwd` into `out`, sorted with
// directories first (then files alphabetically), `..` always at the top
// unless already at root.  Skips symlinks/special files; when
// `st.only_dot_locked` is true, plain files without a `.locked` suffix are
// also hidden so the picker shows only decryptable candidates.
bool collect_entries(FileBrowserState& st,
                     std::vector<BrowserEntry>& out) {
    out.clear();
    std::vector<BrowserEntry> dirs;
    std::vector<BrowserEntry> files;
    std::error_code ec;
    std::filesystem::directory_iterator it;
    try {
        it = std::filesystem::directory_iterator(st.cwd, ec);
    } catch (...) {
        return false;
    }
    if (ec) return false;
    for (; it != std::filesystem::directory_iterator(); ++it) {
        const auto& entry = *it;
        std::error_code rec_ec;
        bool is_dir = entry.is_directory(rec_ec);
        bool is_reg = !is_dir && entry.is_regular_file(rec_ec);
        // Skip everything that is neither dir nor regular (symlinks,
        // sockets, fifos, devices, broken entries).
        if (!is_dir && !is_reg) continue;
        // Filter: when listing for *.locked selection, hide files that don't
        // end with ".locked"; directories are always shown (for navigation).
        if (st.only_dot_locked && is_reg) {
            const auto& p = entry.path();
            auto fname = p.filename().string();
            if (fname.size() < 7 ||
                fname.compare(fname.size() - 7, 7, ".locked") != 0) {
                continue;
            }
        }
        BrowserEntry be;
        be.path = entry.path();
        std::string name = be.path.filename().string();
        if (name.empty()) continue;
        be.display = name;
        if (is_dir) {
            be.display += "/";
            be.is_dir = true;
            dirs.push_back(be);
        } else {
            files.push_back(be);
        }
    }
    auto cmp = [](const BrowserEntry& a, const BrowserEntry& b) {
        return a.display < b.display;
    };
    std::sort(dirs.begin(), dirs.end(), cmp);
    std::sort(files.begin(), files.end(), cmp);
    bool at_root = (st.cwd == st.cwd.root_directory());
    if (!at_root) {
        BrowserEntry up;
        up.display = "..";
        up.path = st.cwd.parent_path();
        up.is_up = true;
        up.is_dir = true;
        out.push_back(up);
    }
    for (auto& d : dirs) out.push_back(std::move(d));
    for (auto& f : files) out.push_back(std::move(f));
    return true;
}

// Try chdir to `target`. On success clears any prior unreadable error and
// returns true; on failure sets an error message string (so the menu still
// renders something) and returns false.
bool try_chdir(FileBrowserState& st,
               const std::filesystem::path& target) {
    std::error_code ec;
    auto abs = std::filesystem::absolute(target, ec);
    if (ec) {
        st.unreadable = std::string{tr(Str::Tui_file_browser_unreadable)};
        return false;
    }
    std::filesystem::directory_iterator it;
    try {
        it = std::filesystem::directory_iterator(abs, ec);
    } catch (...) {
        st.unreadable = std::string{tr(Str::Tui_file_browser_unreadable)};
        return false;
    }
    if (ec) {
        st.unreadable = std::string{tr(Str::Tui_file_browser_unreadable)};
        return false;
    }
    st.cwd = abs;
    st.unreadable.clear();
    return true;
}

// Compute selection-prefix for one entry given the current selection state:
//   file   : "[*]" if directly selected, else "[ ]".
//   dir    : "[-]" if a selected path lives inside this directory's subtree,
//            else "[ ]".
//   ".."   : always "[ ]".
// The string is appended to the entry display as: "<prefix> <display>".
std::string selection_prefix(const BrowserEntry& e,
                             const FileBrowserState& st) {
    std::error_code ec;
    if (e.is_up) return "[ ]";
    auto abs = std::filesystem::absolute(e.path, ec);
    if (ec) return "[ ]";
    std::string abs_str = abs.string();
    if (e.is_dir) {
        std::string dir_str = abs_str;
        if (!dir_str.empty() && dir_str.back() != '/') dir_str.push_back('/');
        for (const auto& s : st.selected) {
            if (s.size() > dir_str.size() &&
                s.compare(0, dir_str.size(), dir_str) == 0) {
                return "[-]";
            }
        }
        return "[ ]";
    }
    auto it = std::find(st.selected.begin(), st.selected.end(), abs_str);
    return it != st.selected.end() ? "[*]" : "[ ]";
}

// Build a reusable ftxui Component that wraps a Menu of file-browser rows
// plus the title/path/footer chrome.  Returns the Component; the caller is
// expected to use its Render() output directly in their wizard step.
ftxui::Component make_file_browser(FileBrowserState& st) {
    // State lives on the heap so the lambda captures + Menu's `opt.selected`
    // pointer both remain valid for the life of the wizard screen.
    auto display  = std::make_shared<std::vector<std::string>>();
    auto entries  = std::make_shared<std::vector<BrowserEntry>>();
    auto selected = std::make_shared<int>(0);

    auto relabel = [=, &st]() {
        display->clear();
        display->reserve(entries->size());
        for (const auto& e : *entries) {
            display->push_back(selection_prefix(e, st) + " " + e.display);
        }
    };

    auto refresh = [=, &st]() {
        if (!collect_entries(st, *entries)) {
            st.unreadable = std::string{tr(Str::Tui_file_browser_unreadable)};
            entries->clear();
        }
        *selected = 0;
        relabel();
    };
    refresh();

    ftxui::MenuOption opt;
    opt.entries = &*display;
    opt.selected = &*selected;
    opt.on_enter = [=, &st]() {
        if (entries->empty()) return;
        if (*selected < 0 || *selected >= static_cast<int>(entries->size())) return;
        const BrowserEntry& e = (*entries)[static_cast<size_t>(*selected)];
        if (e.is_dir) {
            std::filesystem::path old_cwd = st.cwd;
            if (!try_chdir(st, e.path)) {
                if (!try_chdir(st, initial_browser_dir())) {
                    st.cwd = old_cwd;
                }
            }
            refresh();
        }
    };

    auto menu = ftxui::Menu(opt);

    auto renderer = ftxui::Renderer(menu, [=, &st] {
        ftxui::Elements rows;
        rows.push_back(ftxui::text(tr(Str::Tui_file_browser_title))
                       | ftxui::bold | ftxui::center);
        rows.push_back(ftxui::separator());
        rows.push_back(ftxui::hbox({
            ftxui::text(tr(Str::Tui_file_browser_current_path)) | ftxui::bold,
            ftxui::text(" "),
            ftxui::text(st.cwd.string()) | ftxui::color(ftxui::Color::Cyan)
                | ftxui::flex,
        }));
        if (!st.unreadable.empty()) {
            rows.push_back(ftxui::separator());
            rows.push_back(ftxui::text(st.unreadable)
                           | ftxui::color(ftxui::Color::Red)
                           | ftxui::center);
        }
        rows.push_back(ftxui::separator());
        rows.push_back(menu->Render() | ftxui::flex);
        return ftxui::vbox(rows) | ftxui::border;
    });

    // Menu doesn't intercept Space; we catch it here to toggle file
    // selection (Enter already routes to Menu->on_enter via Menu's own
    // event handler in ftxui/component/menu.cpp).
    return renderer | ftxui::CatchEvent([=, &st](ftxui::Event ev) {
        if (ev != ftxui::Event::Character(' ')) return false;
        if (entries->empty()) return true;
        if (*selected < 0 || *selected >= static_cast<int>(entries->size())) {
            return true;
        }
        const BrowserEntry& e = (*entries)[static_cast<size_t>(*selected)];
        if (e.is_dir || e.is_up) return true;
        auto abs = std::filesystem::absolute(e.path);
        std::string key = abs.string();
        auto it = std::find(st.selected.begin(), st.selected.end(), key);
        if (it == st.selected.end()) {
            st.selected.push_back(key);
        } else {
            st.selected.erase(it);
        }
        relabel();
        return true;
    });
}

// ---------------------------------------------------------------------------
// Validation: per-step returns a non-empty Str id on failure (= an error
// message id rendered above the wizard buttons of that step), or
// Str::Str_sentinel on success.  On the password step we reuse the
// full-form `validate_*()` routine so the README-published validation rules
// (level range, password-confirm match, etc.) stay in lock-step with the
// CLI.
// ---------------------------------------------------------------------------
Str validate_encrypt_step_files(const EncryptForm& f) {
    if (f.files.empty()) return Str::Tui_err_select_at_least_one_file;
    return Str::Str_sentinel;
}

Str validate_encrypt_step_compress(const EncryptForm& f) {
    if (f.compression == 2) {
        char* endp = nullptr;
        long v = std::strtol(f.level.c_str(), &endp, 10);
        if (endp == f.level.c_str() || *endp != '\0' || v < 1 || v > 22) {
            return Str::Tui_level_range_error;
        }
    }
    return Str::Str_sentinel;
}

Str validate_encrypt_step_password(const EncryptForm& f) {
    if (f.password.empty()) return Str::Tui_password_empty;
    if (f.password != f.password_confirm) return Str::Tui_password_mismatch;
    return Str::Str_sentinel;
}

Str validate_decrypt_step_files(const DecryptForm& f) {
    if (f.files.empty()) return Str::Tui_err_select_at_least_one_file;
    return Str::Str_sentinel;
}

Str validate_decrypt_step_password(const DecryptForm& f) {
    if (f.password.empty()) return Str::Tui_password_empty;
    return Str::Str_sentinel;
}

// ---------------------------------------------------------------------------
// Generic wizard runner — given the title, per-step names, a function that
// returns the body Component for step `i`, and a `validate_step(i)`
// callback, drives a single ScreenInteractive until the user hits Back /
// Next / Finish / Cancel.  `finish()` is invoked only after `validate_step`
// of the final step returns ok; it returns the Disposition the wizard
// should report to the orchestrator.
//
// Lifecycle note: `make_step(i)` is called once for every step at
// wizard startup (NOT lazily), so all step components stay alive across
// navigation; Container::Tab swaps which one is rendered/focused without
// destroying-and-rebuilding.  `st` (FileBrowserState) outlives any of
// these component lifetimes because it's stack-allocated in the wizard
// caller.
// ---------------------------------------------------------------------------
 Disposition run_wizard(const std::string& title,
                        const std::vector<Str>& step_names,
                        std::function<ftxui::Component(int)> make_step,
                        std::function<Str(int)> validate_step,
                        std::function<Disposition()> finish) {
    auto screen = ftxui::ScreenInteractive::Fullscreen();

    int total = static_cast<int>(step_names.size());
    int current = 0;
    Disposition chosen = Disposition::Cancelled;

    std::vector<ftxui::Component> step_comps;
    step_comps.reserve(static_cast<size_t>(total));
    for (int i = 0; i < total; ++i) step_comps.push_back(make_step(i));

    int tab = 0;
    auto step_stack = ftxui::Container::Tab(step_comps, &tab);

    Str err_msg = Str::Str_sentinel;

    auto back_btn = ftxui::Button(tr(Str::Tui_btn_back), [&] {
        if (current > 0) {
            --current;
            tab = current;
            err_msg = Str::Str_sentinel;
        }
    });
    auto next_btn = ftxui::Button(tr(Str::Tui_btn_next), [&] {
        Str v = validate_step(current);
        if (v == Str::Str_sentinel) {
            err_msg = Str::Str_sentinel;
            if (current < total - 1) {
                ++current;
                tab = current;
            }
        } else {
            err_msg = v;
        }
    });
    auto finish_btn = ftxui::Button(tr(Str::Tui_btn_done), [&] {
        Str v = validate_step(current);
        if (v == Str::Str_sentinel) {
            err_msg = Str::Str_sentinel;
            chosen = finish();
            screen.Exit();
        } else {
            err_msg = v;
        }
    });
    auto cancel_btn = ftxui::Button(tr(Str::Tui_btn_cancel), [&] {
        chosen = Disposition::Cancelled;
        screen.Exit();
    });

    auto buttons = ftxui::Container::Horizontal({back_btn, next_btn,
                                                  finish_btn, cancel_btn});

    auto buttons_renderer = ftxui::Renderer(buttons, [&] {
        ftxui::Elements row;
        auto back_e = back_btn->Render();
        if (current == 0) back_e = back_e | ftxui::dim;
        row.push_back(back_e);
        row.push_back(ftxui::text("  "));
        if (current < total - 1) {
            row.push_back(next_btn->Render());
            row.push_back(ftxui::text("  "));
        }
        row.push_back(finish_btn->Render());
        row.push_back(ftxui::text("  "));
        row.push_back(cancel_btn->Render());
        return ftxui::hbox(row) | ftxui::center;
    });

    auto body = ftxui::Container::Vertical({step_stack, buttons_renderer});

    auto renderer = ftxui::Renderer(body, [&] {
        ftxui::Elements e;
        e.push_back(ftxui::text(title) | ftxui::bold | ftxui::center);
        // [1/4] [2/4] ... [4/4] pill-bar showing the active step inverted.
        ftxui::Elements pills;
        for (int i = 1; i <= total; ++i) {
            std::string label = "[" + std::to_string(i) + "/" +
                                std::to_string(total) + "]";
            ftxui::Element p = ftxui::text(label);
            if (i == current + 1) {
                p = p | ftxui::inverted | ftxui::bold;
            } else if (i < current + 1) {
                p = p | ftxui::dim;
            }
            pills.push_back(p);
            if (i < total) pills.push_back(ftxui::text("  "));
        }
        e.push_back(ftxui::hbox(pills) | ftxui::center);
        e.push_back(ftxui::separator());
        // Step title: e.g. "Step 2/4: Compression".
        std::string step_title = tr(Str::Tui_wizard_step_prefix) +
                                 std::to_string(current + 1) +
                                 tr(Str::Tui_wizard_step_of) +
                                 std::to_string(total) + ": " +
                                 std::string{tr(step_names[static_cast<size_t>(current)])};
        e.push_back(ftxui::text(step_title) | ftxui::center);
        e.push_back(ftxui::separator());
        e.push_back(step_stack->Render() | ftxui::flex);
        if (err_msg != Str::Str_sentinel) {
            e.push_back(ftxui::separator());
            e.push_back(ftxui::text(tr(err_msg))
                        | ftxui::color(ftxui::Color::Red) | ftxui::center);
        }
        e.push_back(ftxui::separator());
        e.push_back(buttons_renderer->Render());
        return ftxui::vbox(e) | ftxui::border | ftxui::center;
    });

    auto app = renderer | ftxui::CatchEvent([&](ftxui::Event ev) {
        if (ev == ftxui::Event::Escape) {
            chosen = Disposition::Cancelled;
            screen.Exit();
            return true;
        }
        if (ev == ftxui::Event::Tab || ev == ftxui::Event::TabReverse) {
            auto active = body->ActiveChild();
            bool step_active = (active.get() == step_stack.get());
            if (ev == ftxui::Event::Tab && step_active && current == 0) {
                body->SetActiveChild(buttons_renderer.get());
                return true;
            }
            if (ev == ftxui::Event::TabReverse && !step_active) {
                body->SetActiveChild(step_stack.get());
                return true;
            }
        }
        return false;
    });

    screen.Loop(app);
    return chosen;
}

// ---------------------------------------------------------------------------
// Encrypt wizard — 4 steps.
// ---------------------------------------------------------------------------
Disposition show_encrypt_wizard(EncryptForm& form) {
    FileBrowserState bs;
    bs.only_dot_locked = false;
    bs.cwd = initial_browser_dir();

    // Synchronise browser selections with form.files for round-trips.
    for (const auto& p : form.files) bs.selected.push_back(p);

    auto make_step = [&](int i) -> ftxui::Component {
        switch (i) {
             case 0: {
                 auto br = make_file_browser(bs);
                 return ftxui::Renderer(br, [br] {
                     return br->Render();
                 });
             }
            case 1: {
                auto make_btn = [&](int idx) {
                    ftxui::ButtonOption o;
                    o.label = std::string(tr(
                        idx == 0 ? Str::Tui_compress_none
                                 : idx == 1 ? Str::Tui_compress_lz4
                                            : Str::Tui_compress_zstd));
                    o.on_click = [&, idx] { form.compression = idx; };
                    auto b = ftxui::Button(o);
                    return ftxui::Renderer(b, [b, idx, &form] {
                        auto e = b->Render();
                        return (form.compression == idx)
                                   ? (e | ftxui::inverted | ftxui::bold)
                                   : (e | ftxui::dim);
                    });
                };
                auto group = ftxui::Container::Horizontal({
                    make_btn(0), make_btn(1), make_btn(2),
                });
                auto section = ftxui::Renderer(group, [group] {
                    return ftxui::vbox({
                        ftxui::text(tr(Str::Tui_field_compression)) | ftxui::bold,
                        group->Render() | ftxui::center,
                    });
                });
                ftxui::InputOption lo;
                lo.placeholder = "3";
                auto level_input = ftxui::Input(&form.level, lo);
                auto level_row = ftxui::Renderer(level_input, [level_input, &form] {
                    auto e = level_input->Render();
                    if (form.compression != 2) {
                        e = e | ftxui::dim;
                    }
                    return ftxui::hbox({
                        ftxui::text(tr(Str::Tui_field_level)) | ftxui::bold
                            | ftxui::size(ftxui::WIDTH, ftxui::EQUAL, 28),
                        ftxui::separator(),
                        e | ftxui::flex,
                    });
                });
                return ftxui::Container::Vertical({section, level_row});
            }
            case 2: {
                ftxui::InputOption outdir_opt;
                outdir_opt.placeholder = tr(Str::Tui_field_output_dir);
                auto output_input = ftxui::Input(&form.output_dir, outdir_opt);
                auto outdir_row = label_field(tr(Str::Tui_field_output_dir),
                                               output_input);
                ftxui::InputOption jobs_opt;
                jobs_opt.placeholder = "0";
                auto jobs_input = ftxui::Input(&form.jobs, jobs_opt);
                auto jobs_row = label_field(tr(Str::Tui_field_jobs),
                                             jobs_input);
                return ftxui::Container::Vertical({outdir_row, jobs_row});
            }
            default: {
                ftxui::InputOption pw_opt;
                pw_opt.placeholder = tr(Str::Tui_password_first);
                pw_opt.password = true;
                auto password_input = ftxui::Input(&form.password, pw_opt);
                ftxui::InputOption pw2_opt;
                pw2_opt.placeholder = tr(Str::Tui_password_second);
                pw2_opt.password = true;
                auto confirm_input = ftxui::Input(&form.password_confirm, pw2_opt);
                auto pw_row = label_field(tr(Str::Tui_password_first),
                                           password_input);
                auto pw2_row = label_field(tr(Str::Tui_password_second),
                                            confirm_input);
                return ftxui::Container::Vertical({pw_row, pw2_row});
            }
        }
    };

    auto validate_step = [&](int i) -> Str {
        switch (i) {
            case 0: {
                form.files = bs.selected;
                return validate_encrypt_step_files(form);
            }
            case 1: return validate_encrypt_step_compress(form);
            case 2: return Str::Str_sentinel;
            default: return validate_encrypt_step_password(form);
        }
    };

    std::vector<Str> step_names = {
        Str::Tui_step_select_files,
        Str::Tui_step_compress_opts,
        Str::Tui_step_output_concurrency,
        Str::Tui_step_password,
    };

    return run_wizard(tr(Str::Tui_encrypt_form_title),
                       step_names,
                       make_step, validate_step,
                       [&] { form.files = bs.selected;
                             return Disposition::RunEncrypt; });
}

// ---------------------------------------------------------------------------
// Decrypt wizard — 3 steps.
// ---------------------------------------------------------------------------
Disposition show_decrypt_wizard(DecryptForm& form) {
    FileBrowserState bs;
    bs.only_dot_locked = true;
    bs.cwd = initial_browser_dir();

    for (const auto& p : form.files) bs.selected.push_back(p);

    auto make_step = [&](int i) -> ftxui::Component {
        switch (i) {
            case 0: {
                auto br = make_file_browser(bs);
                return ftxui::Renderer(br, [br] {
                    return br->Render();
                });
            }
            case 1: {
                ftxui::InputOption outdir_opt;
                outdir_opt.placeholder = tr(Str::Tui_field_output_dir);
                auto output_input = ftxui::Input(&form.output_dir, outdir_opt);
                auto outdir_row = label_field(tr(Str::Tui_field_output_dir),
                                               output_input);
                ftxui::InputOption jobs_opt;
                jobs_opt.placeholder = "0";
                auto jobs_input = ftxui::Input(&form.jobs, jobs_opt);
                auto jobs_row = label_field(tr(Str::Tui_field_jobs),
                                             jobs_input);
                return ftxui::Container::Vertical({outdir_row, jobs_row});
            }
            default: {
                ftxui::InputOption pw_opt;
                pw_opt.placeholder = tr(Str::Tui_password_first);
                pw_opt.password = true;
                auto password_input = ftxui::Input(&form.password, pw_opt);
                auto pw_row = label_field(tr(Str::Tui_password_first),
                                           password_input);
                return ftxui::Container::Vertical({pw_row});
            }
        }
    };

    auto validate_step = [&](int i) -> Str {
        switch (i) {
            case 0: {
                form.files = bs.selected;
                return validate_decrypt_step_files(form);
            }
            case 1: return Str::Str_sentinel;
            default: return validate_decrypt_step_password(form);
        }
    };

    std::vector<Str> step_names = {
        Str::Tui_step_select_locked,
        Str::Tui_step_output_concurrency,
        Str::Tui_step_password,
    };

    return run_wizard(tr(Str::Tui_decrypt_form_title),
                       step_names,
                       make_step, validate_step,
                       [&] { form.files = bs.selected;
                             return Disposition::RunDecrypt; });
}

// ---------------------------------------------------------------------------
// List picker — a single-screen file browser + "View" button; on View,
// screen.Exit() returns Disposition::RunList and the orchestrator runs
// `run_list` with the selected .locked files (output to plain stdout).
// ---------------------------------------------------------------------------
Disposition show_list_picker(std::vector<std::string>& out_files) {
    FileBrowserState st;
    st.only_dot_locked = true;
    st.cwd = initial_browser_dir();

    Disposition chosen = Disposition::Cancelled;

    auto screen = ftxui::ScreenInteractive::Fullscreen();
    auto br = make_file_browser(st);

    auto view_btn = ftxui::Button(tr(Str::Tui_list_view_btn), [&] {
        if (!st.selected.empty()) {
            out_files = st.selected;
            chosen = Disposition::RunList;
            screen.Exit();
        }
    });
    auto cancel_btn = ftxui::Button(tr(Str::Tui_btn_cancel), [&] {
        chosen = Disposition::Cancelled;
        screen.Exit();
    });

    auto buttons = ftxui::Container::Horizontal({view_btn, cancel_btn});

    auto app = ftxui::Renderer(
        ftxui::Container::Vertical({br, buttons}),
        [&] {
            ftxui::Elements body;
            body.push_back(ftxui::text(tr(Str::Tui_list_select_files))
                           | ftxui::bold | ftxui::center);
            body.push_back(ftxui::separator());
            body.push_back(br->Render());
            body.push_back(ftxui::separator());
            body.push_back(buttons->Render() | ftxui::center);
            return ftxui::vbox(body) | ftxui::border | ftxui::center;
        }) | ftxui::CatchEvent([&](ftxui::Event ev) {
        if (ev == ftxui::Event::Escape) {
            chosen = Disposition::Cancelled;
            screen.Exit();
            return true;
        }
        return false;
    });

    screen.Loop(app);
    return chosen;
}

// ---------------------------------------------------------------------------
// Execute run_list in the plain terminal (alt-screen already exited).
// ---------------------------------------------------------------------------
ExitCode execute_list(const std::vector<std::string>& files) {
    ExitCode rc = ExitCode::Internal;
    try {
        rc = run_list(files);
    } catch (const LockError& e) {
        std::fprintf(stderr, "%s%s\n",
                     color_error(tr(Str::Err_label)).c_str(), e.what());
        rc = e.code();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s%s\n",
                     color_error(tr(Str::Err_label)).c_str(), e.what());
    }
    emit_result(rc);
    return rc;
}

// ---------------------------------------------------------------------------
// "Operation done. Press Enter to return to main menu." — discard the
// consume of \r so the next iteration of the main menu can re-read from
// the controlling tty cleanly.  Implemented with std::getchar() — preserves
// the prior termios-untouched invariant (we never toggle ECHO; the plain
// terminal is already in cooked mode by this point).
// ---------------------------------------------------------------------------
void press_enter_prompt() {
    std::fprintf(stderr, "%s\n", tr(Str::Tui_press_enter_after_op));
    // Drain until newline (or EOF — non-tty invocations shouldn't hang).
    int c;
    while ((c = std::getchar()) != EOF && c != '\n') {
        // discard
    }
}

// ---------------------------------------------------------------------------
// Main menu — 4 items (Encrypt/Decrypt/List/Quit).  Loops back here after
// any wizard returns; only Quit/Esc exits the entire TUI.
// ---------------------------------------------------------------------------
enum class MenuAction { Quit, Encrypt, Decrypt, List };

MenuAction show_main_menu() {
    auto screen = ftxui::ScreenInteractive::Fullscreen();

    int selected = 0;
    std::vector<std::string> entries = {
        std::string(tr(Str::Tui_menu_encrypt)),
        std::string(tr(Str::Tui_menu_decrypt)),
        std::string(tr(Str::Tui_menu_list)),
        std::string(tr(Str::Tui_menu_quit)),
    };

    auto menu = ftxui::Menu(&entries, &selected);

    MenuAction action = MenuAction::Quit;

    auto card = ftxui::Renderer(menu, [&] {
        return ftxui::vbox({
                   ftxui::text(tr(Str::Tui_menu_title))
                       | ftxui::bold | ftxui::center,
                   ftxui::separator(),
                   menu->Render(),
               }) |
               ftxui::border | ftxui::center;
    }) | ftxui::CatchEvent([&](ftxui::Event ev) {
        if (ev == ftxui::Event::Return) {
            switch (selected) {
                case 0: action = MenuAction::Encrypt; break;
                case 1: action = MenuAction::Decrypt; break;
                case 2: action = MenuAction::List;    break;
                default: action = MenuAction::Quit;   break;
            }
            screen.Exit();
            return true;
        }
        if (ev == ftxui::Event::Escape) {
            action = MenuAction::Quit;
            screen.Exit();
            return true;
        }
        return false;
    });

    screen.Loop(card);
    return action;
}

}  // namespace

ExitCode run_tui() {
    if (!stdin_is_tty() || !stderr_is_tty()) {
        std::fprintf(stderr, "%s%s\n",
                     color_error(tr(Str::Err_label)).c_str(),
                     tr(Str::Err_tui_not_a_tty));
        return ExitCode::Arg;
    }
    if (!color_enabled()) {
        std::fprintf(stderr, "%s%s\n",
                     color_error(tr(Str::Err_label)).c_str(),
                     tr(Str::Err_tui_no_color));
        return ExitCode::Arg;
    }
    // Outer main-menu loop:
    while (true) {
        MenuAction next = show_main_menu();
        if (next == MenuAction::Quit) {
            return ExitCode::Ok;
        }
        if (next == MenuAction::Encrypt) {
            EncryptForm f;
            if (show_encrypt_wizard(f) == Disposition::RunEncrypt) {
                (void)execute_encrypt(f);
                press_enter_prompt();
            }
            continue;
        }
        if (next == MenuAction::Decrypt) {
            DecryptForm f;
            if (show_decrypt_wizard(f) == Disposition::RunDecrypt) {
                (void)execute_decrypt(f);
                press_enter_prompt();
            }
            continue;
        }
        if (next == MenuAction::List) {
            std::vector<std::string> selected_files;
            if (show_list_picker(selected_files) == Disposition::RunList) {
                (void)execute_list(selected_files);
                press_enter_prompt();
            }
            continue;
        }
    }
}

}  // namespace lock::tui

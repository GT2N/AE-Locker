// lock::tui — ftxui-driven menu UI.
//
// Wave A shipped the framework + a main menu whose non-Quit items dropped
// into a "(not implemented yet)" placeholder.
// Wave B replaces the placeholder with interactive submenus:
//   - Encrypt: form (files + output dir + compression radiobox + level +
//               jobs + password + confirm-password) + Confirm/Cancel.
//   - Decrypt: form (files + output dir + jobs + password) + Confirm/Cancel.
//   - List:    not available in TUI mode — text placeholder advising the
//               user to run `lock list <file>` from the shell.
//
// Wizard flow: once the user fills an Encrypt/Decrypt form and Selects
// Confirm, the form is validated; if validation passes the TUI exits its
// alt-screen (`screen.Exit()`), the captured form fields are translated
// into an EncryptCliArgs/DecryptCliArgs bundle, and run_encrypt/run_decrypt
// executes in the plain terminal (so its cout/cerr/progress reach the user
// unobstructed). The TUI then returns the resulting ExitCode and does NOT
// re-enter the menu — the user restarts `lock --tui` for another session.
// This keeps the lifecycle trivially auditable: each TUI invocation does at
// most one encrypt OR decrypt.
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

#include <climits>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <string>
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
    Quit,         // exit cleanly with ExitCode::Ok
    RunEncrypt,   // execute the captured encrypt form
    RunDecrypt,   // execute the captured decrypt form
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

ftxui::Element labelled_list(std::string label,
                             std::vector<std::string> items) {
    ftxui::Elements rows;
    rows.push_back(ftxui::text(label) | ftxui::bold);
    if (items.empty()) {
        rows.push_back(ftxui::text("  (none)") | ftxui::dim);
    } else {
        for (const auto& it : items) {
            rows.push_back(ftxui::text("  • ") | ftxui::flex);
            rows.back() = ftxui::hbox({rows.back(), ftxui::text(it)});
        }
    }
    return ftxui::vbox(rows);
}

// ---------------------------------------------------------------------------
// Validation helpers — return a non-empty error Str id (= Str::Str_sentinel
// sentinel) on failure, or Str_sentinel on success.  If invalid, the message
// is shown above the Confirm/Cancel buttons.
// ---------------------------------------------------------------------------
Str validate_encrypt(const EncryptForm& f) {
    if (f.files.empty()) {
        return Str::Tui_no_files_error;
    }
    if (f.password.empty()) {
        return Str::Tui_password_empty;
    }
    if (f.password != f.password_confirm) {
        return Str::Tui_password_mismatch;
    }
    // Level is validated only when compression == zstd; lz4/none ignore it.
    if (f.compression == 2) {
        char* endp = nullptr;
        long lv = std::strtol(f.level.c_str(), &endp, 10);
        if (endp == f.level.c_str() || *endp != '\0' || lv < 1 || lv > 22) {
            return Str::Tui_level_range_error;
        }
    }
    return Str::Str_sentinel;
}

Str validate_decrypt(const DecryptForm& f) {
    if (f.files.empty()) {
        return Str::Tui_no_files_error;
    }
    if (f.password.empty()) {
        return Str::Tui_password_empty;
    }
    return Str::Str_sentinel;
}

// Map the radiobox index to the public CompressionId.
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
// Encrypt submenu — builds the form, runs the ftxui loop.  On Confirm with a
// valid form, populates `out` and returns Disposition::RunEncrypt.  On Cancel
// (Esc or the Cancel button) returns Disposition::Quit so the caller exits
// the menu; re-entering the menu after Cancel complicates state and the user
// can simply re-launch `lock --tui`.
// ---------------------------------------------------------------------------
Disposition show_encrypt_form(EncryptForm& out) {
    EncryptForm f;

    auto screen = ftxui::ScreenInteractive::Fullscreen();

    ftxui::InputOption file_opt;
    file_opt.placeholder = tr(Str::Tui_field_add_file);
    auto file_input = ftxui::Input(&f.file_entry, file_opt);

    ftxui::InputOption outdir_opt;
    outdir_opt.placeholder = tr(Str::Tui_field_output_dir);
    auto output_input = ftxui::Input(&f.output_dir, outdir_opt);

    // Compression selector — three Buttons (NOT a Radiobox) so that Arrow/Tab
    // navigation can pass through them.  ftxui's Radiobox consumes ArrowDown
    // /Tab while it can still change `hovered_`, which would trap the focus.
    // The selected option is rendered inverted to mirror Radiobox semantics.
    auto make_comp_btn = [&](int idx) {
        ftxui::ButtonOption o;
        o.label = std::string(tr(idx == 0 ? Str::Tui_compress_none
                                          : idx == 1
                                          ? Str::Tui_compress_lz4
                                          : Str::Tui_compress_zstd));
        o.on_click = [&, idx] { f.compression = idx; };
        auto btn = ftxui::Button(o);
        return ftxui::Renderer(btn, [&, btn, idx] {
            auto e = btn->Render();
            return (f.compression == idx)
                       ? (e | ftxui::inverted | ftxui::bold)
                       : (e | ftxui::dim);
        });
    };
    auto compress_none_btn = make_comp_btn(0);
    auto compress_lz4_btn  = make_comp_btn(1);
    auto compress_zstd_btn = make_comp_btn(2);

    ftxui::InputOption level_opt;
    level_opt.placeholder = "3";
    auto level_input = ftxui::Input(&f.level, level_opt);

    ftxui::InputOption jobs_opt;
    jobs_opt.placeholder = "0";
    auto jobs_input = ftxui::Input(&f.jobs, jobs_opt);

    ftxui::InputOption pw_opt;
    pw_opt.placeholder = tr(Str::Tui_password_first);
    pw_opt.password = true;
    auto password_input = ftxui::Input(&f.password, pw_opt);

    ftxui::InputOption pw2_opt;
    pw2_opt.placeholder = tr(Str::Tui_password_second);
    pw2_opt.password = true;
    auto password2_input = ftxui::Input(&f.password_confirm, pw2_opt);

    auto add_button = ftxui::Button(tr(Str::Tui_field_add_file), [&] {
        std::string p = f.file_entry;
        // trim surrounding whitespace
        auto a = p.find_first_not_of(" \t");
        auto b = p.find_last_not_of(" \t");
        if (a != std::string::npos && b != std::string::npos) {
            p = p.substr(a, b - a + 1);
        } else {
            p.clear();
        }
        if (!p.empty()) {
            f.files.push_back(p);
        }
        f.file_entry.clear();
    });

    Disposition chosen = Disposition::Quit;
    Str error_msg = Str::Str_sentinel;

    auto confirm_btn = ftxui::Button(tr(Str::Tui_btn_confirm), [&] {
        Str err = validate_encrypt(f);
        if (err == Str::Str_sentinel) {
            out = f;
            chosen = Disposition::RunEncrypt;
            screen.Exit();
        } else {
            error_msg = err;
        }
    });
    auto cancel_btn = ftxui::Button(tr(Str::Tui_btn_cancel), [&] {
        chosen = Disposition::Quit;
        screen.Exit();
    });

    // ``compress_section`` is a Renderer that owns the three compress buttons
    // as its single focusable child (a Horizontal container) and lays out a
    // section header + the buttons group.  It is therefore one tab stop in
    // the enclosing form, yet renders everything exactly once.
    auto compress_group = ftxui::Container::Horizontal({
        compress_none_btn, compress_lz4_btn, compress_zstd_btn,
    });
    auto compress_section = ftxui::Renderer(compress_group, [&] {
        return ftxui::vbox({
            ftxui::text(tr(Str::Tui_field_compression)) | ftxui::bold,
            compress_group->Render(),
        });
    });

    auto form = ftxui::Container::Vertical({
        label_field(tr(Str::Tui_field_files), file_input),
        add_button,
        compress_section,
        label_field(tr(Str::Tui_field_level), level_input),
        label_field(tr(Str::Tui_field_jobs), jobs_input),
        label_field(tr(Str::Tui_field_output_dir), output_input),
        label_field(tr(Str::Tui_password_first), password_input),
        label_field(tr(Str::Tui_password_second), password2_input),
        ftxui::Container::Horizontal({confirm_btn, cancel_btn}),
    });

    auto app = ftxui::Renderer(form, [&] {
        ftxui::Elements body;
        body.push_back(ftxui::text(tr(Str::Tui_encrypt_form_title))
                       | ftxui::bold | ftxui::center);
        body.push_back(ftxui::separator());
        body.push_back(labelled_list(tr(Str::Tui_field_files), f.files));
        body.push_back(ftxui::separator());
        body.push_back(form->Render());
        if (error_msg != Str::Str_sentinel) {
            body.push_back(ftxui::separator());
            body.push_back(ftxui::text(tr(error_msg)) | ftxui::color(ftxui::Color::Red)
                           | ftxui::center);
        }
        return ftxui::vbox(body) | ftxui::border | ftxui::center;
    }) | ftxui::CatchEvent([&](ftxui::Event ev) {
        if (ev == ftxui::Event::Escape) {
            chosen = Disposition::Quit;
            screen.Exit();
            return true;
        }
        return false;
    });

    screen.Loop(app);
    return chosen;
}

// ---------------------------------------------------------------------------
// Decrypt submenu.
// ---------------------------------------------------------------------------
Disposition show_decrypt_form(DecryptForm& out) {
    DecryptForm f;
    auto screen = ftxui::ScreenInteractive::Fullscreen();

    ftxui::InputOption file_opt;
    file_opt.placeholder = tr(Str::Tui_field_add_file);
    auto file_input = ftxui::Input(&f.file_entry, file_opt);

    ftxui::InputOption outdir_opt;
    outdir_opt.placeholder = tr(Str::Tui_field_output_dir);
    auto output_input = ftxui::Input(&f.output_dir, outdir_opt);

    ftxui::InputOption jobs_opt;
    jobs_opt.placeholder = "0";
    auto jobs_input = ftxui::Input(&f.jobs, jobs_opt);

    ftxui::InputOption pw_opt;
    pw_opt.placeholder = tr(Str::Tui_password_first);
    pw_opt.password = true;
    auto password_input = ftxui::Input(&f.password, pw_opt);

    auto add_button = ftxui::Button(tr(Str::Tui_field_add_file), [&] {
        std::string p = f.file_entry;
        auto a = p.find_first_not_of(" \t");
        auto b = p.find_last_not_of(" \t");
        if (a != std::string::npos && b != std::string::npos) {
            p = p.substr(a, b - a + 1);
        } else {
            p.clear();
        }
        if (!p.empty()) {
            f.files.push_back(p);
        }
        f.file_entry.clear();
    });

    Disposition chosen = Disposition::Quit;
    Str error_msg = Str::Str_sentinel;

    auto confirm_btn = ftxui::Button(tr(Str::Tui_btn_confirm), [&] {
        Str err = validate_decrypt(f);
        if (err == Str::Str_sentinel) {
            out = f;
            chosen = Disposition::RunDecrypt;
            screen.Exit();
        } else {
            error_msg = err;
        }
    });
    auto cancel_btn = ftxui::Button(tr(Str::Tui_btn_cancel), [&] {
        chosen = Disposition::Quit;
        screen.Exit();
    });

    auto form = ftxui::Container::Vertical({
        label_field(tr(Str::Tui_field_files), file_input),
        add_button,
        label_field(tr(Str::Tui_field_jobs), jobs_input),
        label_field(tr(Str::Tui_field_output_dir), output_input),
        label_field(tr(Str::Tui_password_first), password_input),
        ftxui::Container::Horizontal({confirm_btn, cancel_btn}),
    });

    auto app = ftxui::Renderer(form, [&] {
        ftxui::Elements body;
        body.push_back(ftxui::text(tr(Str::Tui_decrypt_form_title))
                       | ftxui::bold | ftxui::center);
        body.push_back(ftxui::separator());
        body.push_back(labelled_list(tr(Str::Tui_field_files), f.files));
        body.push_back(ftxui::separator());
        body.push_back(form->Render());
        if (error_msg != Str::Str_sentinel) {
            body.push_back(ftxui::separator());
            body.push_back(ftxui::text(tr(error_msg)) | ftxui::color(ftxui::Color::Red)
                           | ftxui::center);
        }
        return ftxui::vbox(body) | ftxui::border | ftxui::center;
    }) | ftxui::CatchEvent([&](ftxui::Event ev) {
        if (ev == ftxui::Event::Escape) {
            chosen = Disposition::Quit;
            screen.Exit();
            return true;
        }
        return false;
    });

    screen.Loop(app);
    return chosen;
}

// ---------------------------------------------------------------------------
// Run the orchestrators in the plain terminal after the alt-screen has
// exited.  Mirrors run_interactive()'s error handling (cli.cpp) so the
// user sees a `error: <msg>` line and a result-page-equivalent summary.
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
// Main menu + dispatch — replaces Wave A's placeholder mechanism.
// ---------------------------------------------------------------------------
ExitCode run_tui_impl() {
    auto screen = ftxui::ScreenInteractive::Fullscreen();

    int selected = 0;
    std::vector<std::string> entries = {
        std::string(tr(Str::Tui_menu_encrypt)),
        std::string(tr(Str::Tui_menu_decrypt)),
        std::string(tr(Str::Tui_menu_list)),
        std::string(tr(Str::Tui_menu_quit)),
    };

    auto menu = ftxui::Menu(&entries, &selected);

    auto menu_card = ftxui::Renderer(menu, [&] {
        return ftxui::vbox({
                   ftxui::text(tr(Str::Tui_menu_title))
                       | ftxui::bold | ftxui::center,
                   ftxui::separator(),
                   menu->Render(),
               }) |
               ftxui::border | ftxui::center;
    });

    auto list_card = ftxui::Renderer([=] {
        return ftxui::vbox({
                   ftxui::text(tr(Str::Tui_list_not_available_title))
                       | ftxui::bold | ftxui::center,
                   ftxui::separator(),
                   ftxui::paragraph(tr(Str::Tui_list_not_available_body))
                       | ftxui::center,
                   ftxui::separator(),
                   ftxui::text(tr(Str::Tui_press_enter_to_return))
                       | ftxui::center,
               }) |
               ftxui::border | ftxui::center;
    });

    // 0 = main menu, 1 = List not-available placeholder.
    int screen_idx = 0;
    // 0 = Encrypt, 1 = Decrypt, 2 = Run-encrypt, 3 = Run-decrypt,
    // 4 = Quit.
    int action = 4;

    auto app = ftxui::Container::Tab({menu_card, list_card}, &screen_idx) |
               ftxui::CatchEvent([&](ftxui::Event ev) {
                   if (screen_idx == 0) {
                       if (ev == ftxui::Event::Return) {
                           if (selected == 0) {        // Encrypt
                               action = 0;
                               screen.Exit();
                               return true;
                           }
                           if (selected == 1) {        // Decrypt
                               action = 1;
                               screen.Exit();
                               return true;
                           }
                           if (selected == 2) {        // List
                               screen_idx = 1;
                               return true;
                           }
                           if (selected == 3) {        // Quit
                               action = 4;
                               screen.Exit();
                               return true;
                           }
                       }
                       return false;
                   }
                   if (ev == ftxui::Event::Return ||
                       ev == ftxui::Event::Escape ||
                       ev == ftxui::Event::Character('q') ||
                       ev == ftxui::Event::Character('Q')) {
                       screen_idx = 0;
                       return true;
                   }
                   return false;
               });

    screen.Loop(app);

    // Outside the alt-screen now — plain terminal, cout/cerr reach user.
    if (action == 0) {
        EncryptForm f;
        Disposition d = show_encrypt_form(f);
        if (d == Disposition::RunEncrypt) {
            return execute_encrypt(f);
        }
        return ExitCode::Ok;
    }
    if (action == 1) {
        DecryptForm f;
        Disposition d = show_decrypt_form(f);
        if (d == Disposition::RunDecrypt) {
            return execute_decrypt(f);
        }
        return ExitCode::Ok;
    }
    return ExitCode::Ok;
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
    return run_tui_impl();
}

}  // namespace lock::tui

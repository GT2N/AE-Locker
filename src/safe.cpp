#include <ae-locker/safe.hpp>
#include <ae-locker/errors.hpp>
#include <ae-locker/i18n.hpp>
#include <ae-locker/term.hpp>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <termios.h>
#include <unistd.h>

namespace ae_locker {

namespace {

constexpr std::size_t kMaxPasswordBytes = 4096;

std::string read_line_from_fd(int fd) {
    std::string buf;
    buf.reserve(128);
    char chunk;
    while (true) {
        ssize_t n = ::read(fd, &chunk, 1);
        if (n < 0) {
            throw LockError(ExitCode::Io, tr(Str::Err_pw_read_failed));
        }
        if (n == 0) {
            break;
        }
        if (chunk == '\n') {
            break;
        }
        if (buf.size() >= kMaxPasswordBytes) {
            throw LockError(ExitCode::Arg, tr(Str::Err_pw_exceeds_max));
        }
        buf.push_back(chunk);
    }
    if (!buf.empty() && buf.back() == '\r') {
        buf.pop_back();
    }
    return buf;
}

PasswordResult read_interactive() {
    // When stdin is a tty we prompt from it directly so the operator's
    // input is never mixed with the controlling /dev/tty.  When stdin is
    // redirected (pipe / file / here-doc) we still read from stdin —
    // most non-interactive use (scripted runs, harness tests) pipes the
    // password via stdin and there is no controlling /dev/tty available.
    // We do NOT turn echo off in the redirected case: the input is already
    // visible to whoever set up the pipe, and disabling echo on a non-tty
    // fd is a no-op anyway.
    int read_fd = -1;
    term::TermiosState state;
    bool echo_disabled = false;

    if (::isatty(STDIN_FILENO)) {
        read_fd = STDIN_FILENO;
        try {
            term::disable_echo(read_fd, state);
            echo_disabled = true;
        } catch (const std::exception& e) {
            std::string what = e.what();
            std::string msg = (what.find("tcgetattr") != std::string::npos)
                                  ? tr(Str::Err_term_getattr)
                                  : tr(Str::Err_term_setattr);
            if (I18n::current() == Lang::En) {
                msg = what;
            }
            throw LockError(ExitCode::Io, msg);
        }
    } else {
        read_fd = STDIN_FILENO;
    }
    struct EchoGuard {
        int fd; bool& on; term::TermiosState& state;
        ~EchoGuard() { if (on) term::restore_echo(fd, state); }
    } restore{read_fd, echo_disabled, state};
    (void)restore;

    std::cerr << tr(Str::Prompt_enter) << std::flush;
    std::string pw = read_line_from_fd(read_fd);
    std::cerr << "\n";

    std::cerr << tr(Str::Prompt_confirm) << std::flush;
    std::string pw2 = read_line_from_fd(read_fd);
    std::cerr << "\n";

    if (pw != pw2) {
        throw LockError(ExitCode::Arg, tr(Str::Prompt_password_mismatch));
    }
    if (pw.empty()) {
        throw LockError(ExitCode::Arg, tr(Str::Prompt_password_empty));
    }

    PasswordResult result;
    result.password = std::move(pw);
    return result;
}

PasswordResult read_from_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw LockError(ExitCode::Io,
                        std::string(tr(Str::Err_pw_open)) + path);
    }
    std::string buf;
    char tmp[kMaxPasswordBytes];
    f.read(tmp, kMaxPasswordBytes);
    auto got = static_cast<std::size_t>(f.gcount());
    buf.assign(tmp, got);
    if (f.gcount() == static_cast<std::streamsize>(kMaxPasswordBytes)) {
        char probe;
        f.read(&probe, 1);
        if (f.gcount() > 0) {
            throw LockError(ExitCode::Arg, tr(Str::Err_pw_too_long));
        }
    }
    if (!buf.empty() && buf.back() == '\n') {
        buf.pop_back();
        if (!buf.empty() && buf.back() == '\r') {
            buf.pop_back();
        }
    }
    if (buf.empty()) {
        throw LockError(ExitCode::Arg,
                        std::string(tr(Str::Err_pw_empty_file)) + path);
    }
    PasswordResult result;
    result.password = std::move(buf);
    result.warn = tr(Str::Warn_unsafe_file_short);
    return result;
}

PasswordResult read_from_env(const std::string& env_name) {
    const char* v = std::getenv(env_name.c_str());
    if (v == nullptr) {
        throw LockError(ExitCode::Arg,
                        std::string(tr(Str::Err_pw_env_unset)) + env_name + "'");
    }
    if (v[0] == '\0') {
        throw LockError(ExitCode::Arg,
                        std::string(tr(Str::Err_pw_env_empty)) + env_name + "'");
    }
    PasswordResult result;
    result.password = v;
    if (I18n::current() == Lang::Zh) {
        result.warn = std::string(tr(Str::Warn_unsafe_env_short)) + env_name +
                      "'——环境变量可能通过 /proc/PID/environ 泄漏";
    } else {
        result.warn = std::string(tr(Str::Warn_unsafe_env_short)) + env_name +
                      "' — env vars may leak via /proc/PID/environ";
    }
    return result;
}

}  // anonymous namespace

PasswordResult acquire_password(const PasswordRequest& req) {
    if (req.mode == PasswordMode::FromFile && !req.no_safe) {
        throw LockError(ExitCode::Arg, tr(Str::Warn_password_unsafe_file));
    }
    if (req.mode == PasswordMode::FromEnvironment && !req.no_safe) {
        throw LockError(ExitCode::Arg, tr(Str::Warn_password_unsafe_env));
    }

    switch (req.mode) {
        case PasswordMode::Interactive:
            return read_interactive();
        case PasswordMode::FromFile:
            return read_from_file(req.file_path);
        case PasswordMode::FromEnvironment:
            return read_from_env(req.env_var_name);
    }
    throw LockError(ExitCode::Internal, tr(Str::Err_pw_invalid_mode));
}

}  // namespace ae_locker

#pragma once

#include <termios.h>
#include <unistd.h>

namespace ae_locker::term {

// Captures termios state so restore_echo() can put it back.
// `valid` is false until disable_echo() succeeds.
struct TermiosState {
    struct termios original{};
    bool valid = false;
};

// Disable echo on `fd`, saving original attributes into `state`.
// Throws std::runtime_error on tcgetattr/tcsetattr failure.
// The caller MUST ensure restore_echo(fd, state) runs (RAII recommended)
// so the terminal is not left with echo disabled on a throw.
void disable_echo(int fd, TermiosState& state);

// Restore attributes saved by disable_echo(). No-op if `state.valid`
// is false. tcsetattr failure here is silently ignored (this may be
// called from a destructor/cleanup path and must not throw).
void restore_echo(int fd, TermiosState& state);

// Open /dev/tty read/write. Returns fd >= 0.
// Throws std::runtime_error if /dev/tty cannot be opened (no
// controlling terminal — e.g. stdin redirected with no tty).
// Caller owns the returned fd (use FdGuard).
int open_tty();

// RAII wrapper that closes an fd on destruction. Move-only.
struct FdGuard {
    int fd = -1;

    ~FdGuard();
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;

    FdGuard(FdGuard&& other) noexcept : fd(other.fd) { other.fd = -1; }
    FdGuard& operator=(FdGuard&& other) noexcept;

    explicit FdGuard(int f) : fd(f) {}
    FdGuard() = default;
};

// Publish a pointer to the saved termios state so a signal handler can
// restore it even when stack unwinding does not run (default-terminated
// SIGINT/SIGTERM/...). Must be called ONLY with the address of a termios
// whose contents are already valid for tcsetattr. Pass nullptr to
// unregister (no-op restore in the handler).
void register_saved_termios(const struct termios* p) noexcept;

// Async-signal-safe terminal cleanup. Restores the published termios to
// STDERR/STDIN/STDOUT (and /dev/tty if openable) via tcsetattr, writes the
// ANSI reset sequence to STDERR, then resets the signal to default and
// _exit(128 + signo). MUST be async-signal-safe (no malloc, no iostream,
// no libc stdio).
[[noreturn]] void restore_terminal_sighandler(int signo) noexcept;

// Install restore_terminal_sighandler for SIGINT, SIGTERM, SIGQUIT, SIGHUP,
// SIGPIPE using sigaction with SA_RESETHAND (one-shot; no SA_NODEFER, no
// SA_RESTART). Returns 0 on success, -1 on any failure (errno preserved).
int install_signal_handlers() noexcept;

}  // namespace ae_locker::term

#include <ae-locker/term.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <atomic>
#include <csignal>
#include <cstddef>
#include <stdexcept>

namespace ae_locker::term {

namespace {

// Atomically published pointer to the termios state captured by
// disable_echo(). The async-signal handler reads this (acquire) to restore
// the original terminal attributes when the process is default-terminated
// by SIGINT/SIGTERM/SIGQUIT/SIGHUP/SIGPIPE — paths where stack unwinding
// does not run and RAII destructors (EchoGuard) are skipped.
std::atomic<const struct termios*> g_saved_termios{nullptr};

// ANSI reset sequence emitted on signal-driven exit. Order matters: cursor
// show, then alt-screen off (so the saved screen is restored), then mouse
// tracking modes off (1006/1003/1002/1000), then legacy alt-screen off,
// SGR reset, cursor-keys application mode off, SI default charset. Each
// terminal ignores unknown sequences, so emitting the whole bundle on
// every signal-driven exit is safe regardless of which features the
// preceding code actually enabled.
constexpr const char kResetSeq[] =
    "\x1b[?25h"      // cursor show
    "\x1b[?1049l"    // alt-screen off
    "\x1b[?1006l"    // mouse extended mode off
    "\x1b[?1003l"    // mouse any-event tracking off
    "\x1b[?1002l"    // mouse button-event tracking off
    "\x1b[?1000l"    // mouse X10 tracking off
    "\x1b[?47l"      // legacy alt-screen off
    "\x1b[0m"        // SGR reset
    "\x1b[?1l"       // cursor keys application mode off
    "\x0f";          // SI: select default charset

}  // namespace

void disable_echo(int fd, TermiosState& state) {
    if (tcgetattr(fd, &state.original) != 0) {
        throw std::runtime_error("tcgetattr failed on tty");
    }
    struct termios new_attr = state.original;
    new_attr.c_lflag &= static_cast<tcflag_t>(~ECHO);
    state.valid = true;
    // Publish BEFORE disabling so a signal fired between this line and the
    // tcsetattr below will still see a valid termios to restore. If we
    // published after tcsetattr, a signal in that window would skip the
    // reset path (g_saved_termios still null) and leave ECHO off.
    register_saved_termios(&state.original);
    if (tcsetattr(fd, TCSAFLUSH, &new_attr) != 0) {
        // Rollback registration: the live terminal is unchanged, so the
        // handler must not try to restore it. EchoGuard's `if (on)` guard
        // is still safe because echo_disabled (the `on` source) is set
        // true by the caller only after disable_echo returns successfully.
        register_saved_termios(nullptr);
        state.valid = false;
        throw std::runtime_error("tcsetattr failed disabling echo");
    }
}

void restore_echo(int fd, TermiosState& state) {
    if (!state.valid) return;
    // Unregister BEFORE the live tcsetattr so a signal fired during this
    // call does not perform a redundant restore (tcsetattr is already
    // idempotent; an extra restore via the handler on a half-restored
    // terminal is at worst redundant, but unregister keeps it clean).
    register_saved_termios(nullptr);
    (void)tcsetattr(fd, TCSAFLUSH, &state.original);
    // Idempotency guard: a double-restore (handler raced this call, or
    // EchoGuard ran then a second restore was issued) is a safe no-op.
    state.valid = false;
}

int open_tty() {
    int fd = ::open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) {
        throw std::runtime_error(
            "cannot open /dev/tty — interactive password unavailable "
            "(stdin redirected?)");
    }
    return fd;
}

void register_saved_termios(const struct termios* p) noexcept {
    g_saved_termios.store(p, std::memory_order_release);
}

[[noreturn]] void restore_terminal_sighandler(int signo) noexcept {
    const struct termios* const p =
        g_saved_termios.load(std::memory_order_acquire);
    if (p != nullptr) {
        // Restore the saved attrs on every plausible tty fd; ignore all
        // errors (fd may not be a tty, /dev/tty may be unavailable, etc).
        (void)tcsetattr(STDERR_FILENO, TCSAFLUSH, p);
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, p);
        (void)tcsetattr(STDOUT_FILENO, TCSAFLUSH, p);
        const int ttyfd = ::open("/dev/tty", O_WRONLY | O_NOCTTY | O_CLOEXEC);
        if (ttyfd >= 0) {
            (void)tcsetattr(ttyfd, TCSAFLUSH, p);
            (void)::close(ttyfd);
        }
    }
    // Single write — async-signal-safe. Short writes are ignored (we have
    // no way to retry meaningfully inside a signal handler and would only
    // be missing the tail of the reset bundle, which the parent terminal
    // will largely tolerate). sizeof(...) - 1 to drop the trailing NUL.
    constexpr size_t n = sizeof(kResetSeq) - 1;
    (void)::write(STDERR_FILENO, kResetSeq, n);
    // Reset to default disposition and re-raise so the parent shell sees
    // the conventional 128+signo exit status. SA_RESETHAND already
    // cleared the handler, but resetting explicitly is belt-and-braces.
    ::signal(signo, SIG_DFL);
    ::_exit(128 + signo);
}

int install_signal_handlers() noexcept {
    struct sigaction sa{};
    sa.sa_handler = &restore_terminal_sighandler;
    sigemptyset(&sa.sa_mask);
    // SA_RESETHAND: one-shot; handler auto-resets to default so a second
    //   signal during cleanup restores default disposition and terminates.
    // No SA_NODEFER (redundant with SA_RESETHAND).
    // No SA_RESTART (we WANT interrupted syscalls to fail so cleanup runs).
    sa.sa_flags = static_cast<int>(SA_RESETHAND);
    const int signals[] = {SIGINT, SIGTERM, SIGQUIT, SIGHUP, SIGPIPE};
    for (int s : signals) {
        if (::sigaction(s, &sa, nullptr) != 0) {
            g_saved_termios.store(nullptr, std::memory_order_release);
            return -1;
        }
    }
    return 0;
}

FdGuard::~FdGuard() {
    if (fd >= 0) ::close(fd);
}

FdGuard& FdGuard::operator=(FdGuard&& other) noexcept {
    if (this != &other) {
        if (fd >= 0) ::close(fd);
        fd = other.fd;
        other.fd = -1;
    }
    return *this;
}

}  // namespace ae_locker::term

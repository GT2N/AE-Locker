#pragma once

#include <termios.h>
#include <unistd.h>

namespace lock::term {

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

}  // namespace lock::term

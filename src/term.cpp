#include <ae-locker/term.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <stdexcept>

namespace ae_locker::term {

void disable_echo(int fd, TermiosState& state) {
    if (tcgetattr(fd, &state.original) != 0) {
        throw std::runtime_error("tcgetattr failed on tty");
    }
    struct termios new_attr = state.original;
    new_attr.c_lflag &= static_cast<tcflag_t>(~ECHO);
    if (tcsetattr(fd, TCSAFLUSH, &new_attr) != 0) {
        throw std::runtime_error("tcsetattr failed disabling echo");
    }
    state.valid = true;
}

void restore_echo(int fd, TermiosState& state) {
    if (!state.valid) return;
    (void)tcsetattr(fd, TCSAFLUSH, &state.original);
}

int open_tty() {
    int fd = ::open("/dev/tty", O_RDWR | O_NOCTTY);
    if (fd < 0) {
        throw std::runtime_error(
            "cannot open /dev/tty — interactive password unavailable "
            "(stdin redirected?)");
    }
    return fd;
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

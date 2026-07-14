#include <lock/safe.hpp>
#include <lock/term.hpp>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <termios.h>
#include <unistd.h>

namespace lock {

namespace {

constexpr std::size_t kMaxPasswordBytes = 4096;

// RAII: restores echo on `fd` when destroyed. No-op if disable failed.
struct EchoRestore {
    int fd;
    term::TermiosState& state;
    ~EchoRestore() { term::restore_echo(fd, state); }
};

std::string read_line_from_fd(int fd) {
    std::string buf;
    buf.reserve(128);
    char chunk;
    while (true) {
        ssize_t n = ::read(fd, &chunk, 1);
        if (n < 0) {
            throw std::runtime_error("read() from tty failed");
        }
        if (n == 0) {
            break;
        }
        if (chunk == '\n') {
            break;
        }
        if (buf.size() >= kMaxPasswordBytes) {
            throw std::runtime_error("password exceeds maximum length");
        }
        buf.push_back(chunk);
    }
    if (!buf.empty() && buf.back() == '\r') {
        buf.pop_back();
    }
    return buf;
}

PasswordResult read_interactive() {
    term::FdGuard tty(term::open_tty());

    term::TermiosState state;
    term::disable_echo(tty.fd, state);
    EchoRestore restore{tty.fd, state};

    std::cerr << "Enter password: " << std::flush;
    std::string pw = read_line_from_fd(tty.fd);
    std::cerr << "\n";

    std::cerr << "Confirm password: " << std::flush;
    std::string pw2 = read_line_from_fd(tty.fd);
    std::cerr << "\n";

    if (pw != pw2) {
        throw std::runtime_error("passwords do not match");
    }
    if (pw.empty()) {
        throw std::runtime_error("password cannot be empty");
    }

    PasswordResult result;
    result.password = std::move(pw);
    return result;
}

PasswordResult read_from_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open password file: " + path);
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
            throw std::runtime_error("password file exceeds 4 KiB limit");
        }
    }
    if (!buf.empty() && buf.back() == '\n') {
        buf.pop_back();
        if (!buf.empty() && buf.back() == '\r') {
            buf.pop_back();
        }
    }
    if (buf.empty()) {
        throw std::runtime_error("password file is empty: " + path);
    }
    PasswordResult result;
    result.password = std::move(buf);
    result.warn = "password read from file — ensure the file is not logged";
    return result;
}

PasswordResult read_from_env(const std::string& env_name) {
    const char* v = std::getenv(env_name.c_str());
    if (v == nullptr) {
        throw std::runtime_error(
            "environment variable '" + env_name + "' is not set");
    }
    if (v[0] == '\0') {
        throw std::runtime_error(
            "environment variable '" + env_name + "' is empty");
    }
    PasswordResult result;
    result.password = v;
    result.warn = "password read from environment variable '" + env_name +
                  "' — env vars may leak via /proc/PID/environ";
    return result;
}

}  // anonymous namespace

PasswordResult acquire_password(const PasswordRequest& req) {
    if (req.mode == PasswordMode::FromFile && !req.no_safe) {
        throw std::runtime_error(
            "Reading password from a file is considered unsafe "
            "(file contents may leak via fsync logs / core dumps / "
            "process listings). "
            "Re-run with --no-safe to override.");
    }
    if (req.mode == PasswordMode::FromEnvironment && !req.no_safe) {
        throw std::runtime_error(
            "Reading password from an environment variable is considered "
            "unsafe (env vars leak via /proc/PID/environ, ps -E, and "
            "child processes). "
            "Re-run with --no-safe to override.");
    }

    switch (req.mode) {
        case PasswordMode::Interactive:
            return read_interactive();
        case PasswordMode::FromFile:
            return read_from_file(req.file_path);
        case PasswordMode::FromEnvironment:
            return read_from_env(req.env_var_name);
    }
    throw std::runtime_error("invalid password mode");
}

}  // namespace lock

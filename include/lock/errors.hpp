// lock::errors — exit-code enumeration and a typed exception that carries
// one.  Lower-level crypto / container / kdf modules still throw bare
// std::runtime_error (we deliberately do not touch their algorithm code);
// cli_main's top-level catch must therefore classify those by inspecting
// e.what() substrings and map them to an ExitCode.  Code paths that
// originate inside cli.cpp / safe.cpp throw LockError directly with a
// known bucket so the classification step is a no-op for them.
#pragma once

#include <stdexcept>
#include <string>
#include <string_view>

namespace lock {

enum class ExitCode : int {
    Ok       = 0,   // success
    Arg      = 2,   // user-facing argument error (missing/invalid flag, etc.)
    Io       = 3,   // I/O failure (input missing, output mkdir, output exists, RW)
    Crypto   = 4,   // HMAC/GCM/scrypt/RAND integrity failure
    Internal = 5    // uncaught std::exception / unknown condition
};

// Throw `msg` annotated with `code`.  Always returns the supplied code via
// the captured value (run_encrypt / run_decrypt return it).
class LockError : public std::runtime_error {
public:
    LockError(ExitCode code, std::string_view msg)
        : std::runtime_error(std::string(msg)), code_(code) {}

    [[nodiscard]] ExitCode code() const noexcept { return code_; }

private:
    ExitCode code_;
};

}  // namespace lock

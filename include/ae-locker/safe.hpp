#pragma once

#include <string>
#include <string_view>

#include <ae-locker/term.hpp>

namespace ae_locker {

enum class PasswordMode {
    Interactive,
    FromFile,
    FromEnvironment,
};

struct PasswordRequest {
    PasswordMode mode = PasswordMode::Interactive;
    std::string file_path;                          // used iff mode == FromFile
    std::string env_var_name = "LOCK_PASSWORD";      // used iff mode == FromEnvironment
    bool no_safe = false;                            // false ⇒ refuse non-interactive modes
};

struct PasswordResult {
    std::string password;
    std::string warn;
};

// Acquire a password based on `req`. Returns the password (and an optional
// human-readable warning in `warn`), or throws std::runtime_error on
// failure (cancelled, file unreadable, env var missing, unsafe mode
// without --no-safe, passwords do not match, password empty, ...).
[[nodiscard]] PasswordResult acquire_password(const PasswordRequest& req);

}  // namespace ae_locker

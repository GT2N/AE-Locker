// lock::cli_dispatch — public surface of the per-subcommand orchestrators
// (run_encrypt / run_decrypt / run_list) and their argument bundles.
//
// Historically these structs and functions lived inside an anonymous
// namespace in src/cli.cpp, which made them invisible to the rest of the
// translation units. The ftxui-based TUI (src/tui.cpp) needs to invoke the
// same encrypt/decrypt orchestrators so the user never has to leave the
// application to perform a round-trip encryption; lifting only these four
// symbols into the public `lock` namespace — while keeping every other
// parsing / helper internal to cli.cpp — gives the TUI a stable, minimal
// contract without exposing the CLI parser internals.
//
// The implementation continues to live in src/cli.cpp; this header only
// carries the declarations and the in-memory layout of the argument
// bundles so the TUI can construct them by value.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <lock/constants.hpp>   // CompressionId, DEFAULT_CHUNK_SIZE
#include <lock/errors.hpp>       // ExitCode
#include <lock/progress.hpp>     // ProgressTracker
#include <lock/safe.hpp>         // PasswordMode

namespace lock {

// ---------------------------------------------------------------------------
// Encrypt orchestration argument bundle.
// ---------------------------------------------------------------------------
struct EncryptCliArgs {
    std::vector<std::string> files;
    PasswordMode password_mode = PasswordMode::Interactive;
    std::string password_file;
    bool no_safe               = false;
    uint32_t jobs              = 0;
    bool jobs_explicit         = false;
    std::string output_dir;
    uint32_t chunk_size        = static_cast<uint32_t>(DEFAULT_CHUNK_SIZE);
    bool chunk_size_explicit   = false;
    CompressionId compression  = CompressionId::NONE;
    int compression_level      = 3;
    bool verbose               = false;
    bool quiet                 = false;
    bool auto_mode             = false;
    std::string auto_dir;
    int32_t max_depth          = -1;
};

// ---------------------------------------------------------------------------
// Decrypt orchestration argument bundle (encrypt-only `compression` /
// `compression_level` fields omitted).
// ---------------------------------------------------------------------------
struct DecryptCliArgs {
    std::vector<std::string> files;
    PasswordMode password_mode = PasswordMode::Interactive;
    std::string password_file;
    bool no_safe               = false;
    uint32_t jobs              = 0;
    bool jobs_explicit         = false;
    std::string output_dir;
    uint32_t chunk_size        = static_cast<uint32_t>(DEFAULT_CHUNK_SIZE);
    bool chunk_size_explicit   = false;
    bool verbose               = false;
    bool quiet                 = false;
    bool auto_mode             = false;
    std::string auto_dir;
    int32_t max_depth          = -1;
};

// ---------------------------------------------------------------------------
// Per-subcommand orchestrators.
//
// `run_encrypt` / `run_decrypt` are non-interactive with respect to argv
// parsing — the caller fills the argument bundle, then the orchestrator
// acquires the password via the mode carried in the bundle, performs the
// streaming crypto pipeline, and prints progress through `tracker`.
// They may throw `LockError` (carrying the proper ExitCode) or a bare
// `std::runtime_error` for the top-level caller to classify.
// `run_list` writes metadata straight to std::cout and never throws.
// ---------------------------------------------------------------------------
[[nodiscard]] ExitCode run_encrypt(const EncryptCliArgs& args,
                                   ProgressTracker& tracker);
[[nodiscard]] ExitCode run_decrypt(const DecryptCliArgs& args,
                                   ProgressTracker& tracker);
[[nodiscard]] ExitCode run_list(const std::vector<std::string>& files);

}  // namespace lock

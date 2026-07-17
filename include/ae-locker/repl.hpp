// ae_locker::repl — thin wrapper around GNU readline for the `lock --cli` REPL.
//
// The header exposes two small entry points; src/repl.cpp owns all direct
// linkage against libreadline (history list, completion function pointers,
// and generation of completion candidates). When libreadline was not found
// at configure time the implementation simply never compiles its body, and
// callers fall back to `std::getline` in src/cli.cpp's run_interactive().
//
// Nothing in this header depends on readline.h, so downstream TUs do not need
// readline's dev headers in their include path.
#pragma once

#include <string>

namespace ae_locker {

// Read one input line from the user via GNU readline. Emits `prompt`, records
// the returned line into readline's in-memory history (skipping empty/whitespace
// lines), and stores the line content in `out` (newline trimmed). Returns
// false on EOF (Ctrl-D on an empty prompt). Thread-unsafe — the REPL is
// single-threaded by construction.
//
// This call is a no-op when libreadline is absent at compile time; callers must
// guard with `#if LOCK_HAVE_READLINE` and call std::getline themselves.
[[nodiscard]] bool repl_readline(std::string prompt, std::string& out);

// Install the custom Tab completion function (subcommand/flag/argument-aware)
// once per process. Idempotent — safe to call on every iteration of the REPL.
// No-op when libreadline is absent.
void repl_install_completer() noexcept;

}  // namespace ae_locker

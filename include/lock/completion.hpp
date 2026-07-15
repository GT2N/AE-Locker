// lock::completion — runtime generation of shell tab-completion scripts for
// `lock`.  This is Wave B's offline generator: it produces a fully-installed
// -ready script (bash / zsh / fish) purely by string assembly from the CLI's
// own known grammar — no sub-shell spawn, no network calls, no third-party
// completion library.  The output is meant to be `eval`'d / sourced by the
// target shell; the script body itself stays in English regardless of
// `--lang` because shells parse it, not end users.
//
// Public entry point: `print_completion(<shell>, out)` writes the script
// for the supported shell name ("bash" | "zsh" | "fish") to `out` and
// returns true; an unsupported shell name returns false so cli_main can
// surface a localized error to stderr (ExitCode::Arg).
#pragma once

#include <iosfwd>
#include <string>
#include <string_view>

namespace lock {

// Supported shell targets for `lock --completion <shell>`.  Order is used
// by `supported_shells_help()` to render the "(choose: bash, zsh, fish)"
// suffix in error messages — it MUST stay in lock with the table-driven
// grammar in completion.cpp.
enum class CompletionShell {
    Bash,
    Zsh,
    Fish,
};

// True iff `name` is one of "bash" / "zsh" / "fish" (case-sensitive — shells
// are case-sensitive on the scripts they source).
[[nodiscard]] bool is_supported_shell(std::string_view name) noexcept;

// Parse `name` into a CompletionShell; returns false if unsupported.  Used by
// cli_main so the error-message format stays consistent with the rest of
// the CLI.
[[nodiscard]] bool parse_completion_shell(std::string_view name,
                                          CompletionShell& out) noexcept;

// Render "bash, zsh, fish" (the list of supported shells) for embedding in
// localized error messages such as "unsupported shell 'X' (choose: ...)".
[[nodiscard]] std::string_view supported_shells_label() noexcept;

// Write the shell-appropriate completion script to `out` and return true.
// `shell` MUST be one of the supported values.  No diagnostic is printed
// here — the caller decides where the script goes and how errors outside
// this function should be reported.  Output is not affected by `--lang`
// or `--no-color` (completion scripts are parsed by shells, not humans).
void print_completion(CompletionShell shell, std::ostream& out);

// Convenience overload for cli_main's "--completion" / "--completion=X"
// short-circuit: returns `true` and writes the script, or `false` and emits
// nothing.  On `false`, the caller is responsible for emitting a localized
// error (using the existing emit_error/tr pattern) and returning Arg=2.
[[nodiscard]] bool print_completion_for(std::string_view shell_name,
                                        std::ostream& out);

}  // namespace lock

// lock::tui — full-screen TUI entry point. All ftxui includes are kept
// inside src/tui.cpp so this header stays dependency-free and safe to
// pull into cli.cpp without dragging ftxui into the public surface.
#pragma once

#include <lock/errors.hpp>

namespace lock::tui {

// Run the interactive TUI. Returns the process exit code; Ok when the
// user quit cleanly, Arg when invoked in a non-interactive context.
[[nodiscard]] ExitCode run_tui();

}  // namespace lock::tui

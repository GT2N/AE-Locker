#pragma once

namespace ae_locker {

// Entry point invoked by main(). Parses argv and dispatches to
// encryption / decryption / list / interactive handlers.
// Returns the appropriate exit code (0 on success, non-zero on error).
[[nodiscard]] int cli_main(int argc, char** argv);

}  // namespace ae_locker

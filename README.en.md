# lock

[简体中文](README.md) | **English**

`lock` is a command-line file encryption tool written in C++20. It uses **AES-256-CTR** for multi-threaded parallel encryption of file contents, **AES-256-GCM** to encrypt the original filename (making it invisible after encryption), and **HMAC-SHA256** for full-file integrity authentication. The key is derived from the user's passphrase via the **scrypt** KDF. Optional **LZ4 / zstd** compress-then-encrypt is supported: per-chunk independent compression before encryption via `--compress` / `-z` / `--fast`; during decryption the compression algorithm is auto-detected and reversed.

Build toolchain: **Clang + LLD + ThinLTO + Ninja + CMake**.

## Features

- **Optional compression**: each chunk is independently compressed with LZ4 or zstd before encryption; compression and encryption both run in parallel in worker threads; the decompression algorithm is auto-selected from the header (v1 files remain read as-is)
- **AES-256-CTR** for bulk encryption, parallelizable (per-chunk independent IV)
- **AES-256-GCM** used only for filename encryption (small data with authentication)
- **scrypt** KDF derives 64 bytes of key material from the passphrase: 32-byte `file_key` + 32-byte `hmac_key`
- **HMAC-SHA256** covers `header || ciphertext` as the trailing authentication tag
- **Invisible filenames**: the original filename exists only in ciphertext form inside the header; restored from the header on decryption
- **Multi-threading**: `N` compress workers per file in parallel (controlled by `-j N`; the encrypt step is single-threaded serial because v2 IV needs accumulated CT size); files are also processed in parallel
- **Progress bars**: per-file independent + overall progress (hand-written ASCII `[=====>]` renderer, no third-party dependency, in-place refresh)
- **Multiple CLI styles**: subcommand, `-c flag`, `--cli` interactive
- **Multiple password sources**: interactive (default), file (`-p`, requires `--no-safe`), environment variable (`--password-env-var`, requires `--no-safe`)
- **No overwrite**: if `foo.txt.locked` already exists, encryption refuses to proceed and errors out
- **Safety guardrail**: reading passphrases from file/environment is rejected by default; requires explicit `--no-safe` confirmation

## Build

### Common Dependencies

- **Clang 15+** (C++20.coroutine / `std::span`)
- **LLD** (linker, ThinLTO backend)
- **Ninja**
- **CMake 3.25+** (preset uses `CMAKE_CXX_COMPILER_TARGET` and other 3.25+-only toolchain features)
- **OpenSSL 3.x** (provides `EVP_KDF_scrypt`, `EVP_MAC`)
- **(Optional) GNU readline + libtinfo** — provides history and Tab completion for the `--cli` REPL; when not detected, CMake automatically degrades to `std::getline` mode (no history, no completion); other features are unaffected
- **LZ4 v1.9.4 / zstd v1.5.7 / ftxui v5.0.0** are all fetched and statically built by CMake `FetchContent`; no system pre-install needed. First `cmake` configure clones them from GitHub; subsequent builds reuse `build/_deps/`

`CMakePresets.json` ships three presets:

| Preset | Target arch | Linking | Purpose |
|---|---|---|---|
| `default`         | host (x86_64 / aarch64) | dynamic             | Main dev path; output at `build/lock` |
| `debug`           | host                    | dynamic, no ThinLTO | Debugging |
| `aarch64-static`  | aarch64 Linux           | **fully static** (`-static-pie`, no `NEEDED`) | Cross-compile from x86_64 host; output at `build-aarch64/lock` |

All presets share:

- `-flto=thin` + `-Wl,--thinlto-cache-dir=<build>/.lto-cache` (off for `debug`)
- `-fuse-ld=lld` + `--ld-path=$(which ld.lld)`
- `-Wall -Wextra -Wpedantic -Werror -Wconversion -Wimplicit-int-conversion -Wshadow`

> The three presets **do not conflict**: `default` / `debug` output under `build/`, `aarch64-static` outputs under `build-aarch64/`, caches are fully isolated, and you can switch between them in the same source tree.

### Debian / Ubuntu — x86_64 host (most common)

```bash
sudo apt-get install -y clang lld ninja-build cmake libssl-dev libreadline-dev
git clone <repo-url> && cd lock
cmake --preset default       # One-time configure (first run FetchContent-fetches lz4/zstd/ftxui)
cmake --build build          # Incremental build
./build/lock --version
```

`libreadline-dev` can be omitted — if CMake doesn't detect readline, it automatically degrades to the `std::getline` REPL mode (no history, no Tab completion); other features are unaffected.

### Debian / Ubuntu — aarch64 native host (Raspberry Pi OS 64-bit, etc.)

On an aarch64 host, `cmake --preset default` works out of the box — clang's default target on aarch64 hosts is `aarch64-linux-gnu`, fully compatible with the preset. The install and build commands are identical to the x86_64 host path:

```bash
sudo apt-get install -y clang lld ninja-build cmake libssl-dev libreadline-dev
cmake --preset default
cmake --build build
./build/lock --version
```

The output is a dynamically-linked binary, depending on the same-machine `libssl.so.3` / `libstdc++.so.6` / `libreadline.so.8` etc.; to run `lock` on another aarch64 machine with the same distro / glibc generation you'll need to `apt install` the corresponding runtime libs first (or use the cross-compiled static artifact below).

### Debian / Ubuntu — Cross-compile aarch64 **static** binary on x86_64 host

Enable Debian multiarch arm64 and pre-install the cross toolchain plus arm64 static libs. One-time setup:

```bash
# 1) Enable arm64 multiarch
sudo dpkg --add-architecture arm64
sudo apt-get update

# 2) Host tools: clang / lld / ninja / cmake
sudo apt-get install -y clang lld ninja-build cmake

# 3) arm64 binutils (ar/ranlib/strip must match arch format; LLD can link arm64,
#    but archiving still uses arch-specific ar)
sudo apt-get install -y binutils-aarch64-linux-gnu

# 4) Cross glibc + libgcc/libstdc++ static libs
sudo apt-get install -y libc6-dev-arm64-cross g++-aarch64-linux-gnu

# 5) arm64 static OpenSSL + readline + tinfo (multiarch packages, :arm64 suffix)
sudo apt-get install -y libssl-dev:arm64 libreadline-dev:arm64 libtinfo-dev:arm64
```

Then inside the `lock/` source tree:

```bash
cmake --preset aarch64-static          # One-time configure
cmake --build --preset aarch64-static  # Incremental build
# Output at build-aarch64/lock, no NEEDED entries, scp to any standard aarch64
# Linux (glibc 2.31+) and run directly — no runtime libs needed on the target
```

The `cmake/aarch64-linux-gnu.cmake` toolchain file force-links OpenSSL / readline / tinfo / libstdc++ / libgcc / glibc as `.a`, and uses `-static-pie` to produce an ET_DYN binary with no `NEEDED` entries. See "Cross-arch artifacts" below for the supported range.

### macOS

macOS uses Apple's `ld64` by default (not LLD); OpenSSL / readline go through Homebrew. Expose Homebrew's llvm (with lld) and openssl/readline paths explicitly to CMake:

```bash
brew install cmake ninja llvm@18 openssl@3 readline

# On Intel macs, replace /opt/homebrew with /usr/local
export PATH=/opt/homebrew/opt/llvm/bin:$PATH
export OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
export Readline_ROOT=/opt/homebrew/opt/readline

cmake --preset default
cmake --build build
./build/lock --version
```

> The macOS path **has not been tested yet**. ThinLTO + LLD occasionally conflicts with macOS code signing / notarization. If you hit LLD link issues, you can `-DENABLE_THINLTO=OFF` to disable ThinLTO and set `CMAKE_LINKER_TYPE` to `ld64` (or let CMake auto-fallback to the Apple linker).

### Termux on Android — on-device compile

Termux is the **only viable path** to run `lock` on Android: compile directly inside Termux with its bundled clang. Termux clang's default target is `aarch64-linux-android` (Bionic libc); the resulting binary is Bionic-native and runs directly inside Termux. The `dist/arch/aarch64/lock` static artifact (glibc) **cannot** be used in Termux — see "Unsupported platforms — Termux / Android" below.

```bash
# Inside Termux (any 64-bit Android device):
pkg install clang lld ninja cmake openssl readline

# CMakePresets.json's presets assume Debian multiarch layout,
# Termux's prefix is at $PREFIX (default /data/data/com.termux/files/usr),
# which differs from the preset assumption — so presets can't be used directly;
# pass cache vars manually:
cmake -B build -G Ninja \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_THINLTO=ON \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

cmake --build build
./build/lock --version
```

> The Termux on-device compile path **has not been tested yet**. Known risk points:
> 1. FetchContent's first run will `git clone` lz4 / zstd / ftxui from GitHub; if
>    Termux network proxy or disk permissions interfere, you may need to switch to
>    `URL` sources or pre-vendor the sources
> 2. Termux's libtinfo may not exist standalone (readline and ncurses are often
>    merged in Termux); if `find_library(Readline_TINFO_LIBRARY NAMES tinfo ncurses)`
>    can't find `libtinfo`, CMake still links readline but REPL's coloring / cursor
>    control may misbehave in some terminals
> 3. Termux's `mmap` / `getrandom` behavior isn't fully identical to Linux glibc —
>    `RAND_bytes` and streaming I/O should work on Android 6.0+, but on lower Android
>    versions `/dev/urandom` may be unavailable
>
> Feedback welcome after testing — this section will be updated.

## Quick Start

```bash
# Encrypt (interactive passphrase prompt)
./build/lock encrypt secret.txt
# → secret.txt.locked

# Decrypt (same passphrase)
./build/lock decrypt secret.txt.locked -o ./out/
# → ./out/secret.txt  (filename restored from header)

# View file metadata without decryption
./build/lock list secret.txt.locked
```

Multi-file parallel encryption:

```bash
./build/lock encrypt a.txt b.txt c.txt -j 8
```

## Localization (Locale / Language)

`lock` ships with built-in English/Chinese bilingual support. Language is auto-detected by the following priority; `--lang` overrides explicitly. No third-party i18n library dependency.

| Priority | Source | Notes |
|:---:|:---|:---|
| 1 | `--lang zh\|en` (anywhere on the command line) | Explicit, highest priority; later values override earlier ones |
| 2 | `$LC_ALL` | e.g. `zh_CN.UTF-8` → zh; no `zh` substring → en |
| 3 | `$LC_MESSAGES` | Same as above |
| 4 | `$LANG` | Same as above |
| (default) | none set | English (en) |

`-v` / `--verbose` prints a one-line detection trace to stderr:

```
[lang] detected=zh effective=zh (env: LANG=zh_CN.UTF-8)
```

Color output (error prefixes, progress bar fill, password prompts etc.) respects `NO_COLOR` / `CLICOLOR=0` / terminal tty detection, and can also be fully disabled with `--no-color` (which also disables progress bar ANSI cursor control and repaint). Under `--no-color` the progress bar degrades to a single plain-text stderr line per file, for piping or scripting.

`-q` / `--quiet` only suppresses the progress bar; errors still print.

### Usage Examples

```bash
# Chinese localization (CLI prompts, help, progress, error messages)
./build/lock --lang zh encrypt secret.txt

# Affects only this run via env var routing
LC_ALL=zh_CN.UTF-8 ./build/lock encrypt secret.txt

# Show language detection trace
./build/lock encrypt secret.txt -v

# Disable colors and cursor ANSI
./build/lock --no-color encrypt secret.txt -o ./out/

# Pipe mode: auto-detects if stdin is a tty; non-tty doesn't disable echo
printf 'pw\npw\n' | ./build/lock encrypt secret.txt
```

### Exit Code Table

`cli_main` still exposes only an `int` return value (public signature unchanged), but internally returns the following exit codes per scenario:

| Code | Meaning | Trigger scenarios |
|:---:|:---|:---|
| 0 | Success (Ok) | encrypt/decrypt/list completed normally |
| 2 | Argument error (Arg) | Unknown command / missing flag value / unsupported flag value (`--lang fr` / `--compress bogus` etc.) / password mismatch, empty password / no encryptable files / no input files / `--max-depth` used without `--auto` / `--auto` directory doesn't exist |
| 3 | I/O error / input file already exists (Io) | Target `.locked` file already exists (no-overwrite guard) / directory creation failed / file unreadable |
| 4 | Key derivation / auth failure (Auth) | Wrong password on decrypt (HMAC verification failed / file tampered / salt mismatch) |
| 5 | Internal unrecoverable error (Internal) | Exception reaches `cli_main` top-level catch |

The `lock list` subcommand returns 0 even for inputs that are "not `.locked` files" (just prints a note), so scripts can aggregate the success/failure of other subcommands via exit codes.

## Batch Directory Encrypt/Decrypt (`--auto`)

`--auto <dir>` enters batch mode: recursively scans all regular files in the specified directory and mirrors the source subdirectory structure into `-o/--output-dir`, avoiding same-name-file conflicts across subdirectories.

```bash
# Recursively encrypt all files under ./secrets into ./encrypted, mirroring source structure
./build/lock encrypt --auto ./secrets --max-depth 3 -o ./encrypted

# Recursively decrypt: scan ./encrypted/*.locked, use filename restored from header
# as the output filename, mirror subdir structure into ./decrypted
./build/lock decrypt --auto ./encrypted -o ./decrypted
```

Conventions:

- `--auto <dir>`: recursively scan this directory. `-o/--output-dir` **must** be explicitly given as the output root for mirroring source subdir structure.
- `--max-depth <N>`: recursion depth control. `-1` = unlimited (default); `0` = only direct files inside the `--auto` directory; `1` = current level + one level of subdirectories; and so on.
- encrypt: skips `.locked`-suffixed files (prevents self-re-encrypting its own artifacts); only processes regular files.
- decrypt: only processes `.locked`-suffixed regular files; restores the original filename from the header as the output filename.
- skips symlinks (prevents cycle attacks); skips non-regular files (socket/device/fifo).
- Output lands at `-o` as `[source relative path].locked` (encrypt) / `[source relative subdir]/[header-restored filename]` (decrypt), same "exists → refuse" (no overwrite) rule as single-file mode.
- `--auto` and positional file args are mutually exclusive; only one can be given. `--max-depth` alone (without `--auto`) errors out.
- An empty directory (no encryptable/decryptable files) errors with "no eligible files found" (not a silent success).

## Three CLI Styles

| Style | Command |
|---|---|
| **Subcommand (default)** | `lock encrypt <file> [options]` |
| **flag form** | `lock -c encrypt <file> [options]` |
| **Interactive** | `lock --cli` (enters REPL, supports `encrypt` / `decrypt` / `list` / `quit`, plus in-REPL help commands `help` / `?` / `h`) |

### Per-subcommand `--help` / `-h`

`lock --help` prints the overview; appending `--help` (or `-h`) after any subcommand prints only that subcommand's summary, relevant options and examples, and returns immediately with exit code 0 (does NOT actually execute encrypt/decrypt/list even if other args are present):

```bash
lock encrypt --help    # encrypt subcommand-specific help (EN)
lock decrypt --help    # decrypt subcommand-specific help
lock list --help       # list subcommand-specific help
lock encrypt -h        # Identical to --help
lock --lang zh encrypt --help   # Chinese version of encrypt help
lock encrypt foo.txt --help -o out -z   # --help short-circuits, no encryption, exit 0
```

`lock help encrypt` does **not** exist — top-level `help` is still an unknown command (exit 2); only available inside the `--cli` REPL.

### `--cli` REPL in-REPL help commands

Inside `lock --cli`, the REPL accepts additional help commands (only inside the REPL, not exposed as executable subcommands):

| Command | Behavior |
|---|---|
| `help` / `?` / `h` | Prints the same overall help as `lock --help` to STDOUT |
| `help encrypt` / `? encrypt` / `h decrypt` / `? list` etc. | Prints the corresponding subcommand's specific help to STDOUT |
| `help bogus` (or any topic other than encrypt/decrypt/list) | Prints a localized "unknown help topic" error to STDERR; REPL does **not** exit and re-prompts |

The REPL prints a short hint to STDERR on startup, telling the user `help` / `?` / `h` and `quit` are available. `quit` / `exit` / `q` still end the REPL with `ExitCode::Ok`.

### `--cli` REPL readline support

`lock --cli` probes for GNU readline + libtinfo at compile time as an optional link dependency; when both are available the REPL is driven by readline, providing:

- **Line editing**: ←/→/Home/End within-word movement, Ctrl-A / Ctrl-E, Backspace/Delete at cursor position.
- **History**: ↑/↓ to browse current-process input history (non-empty lines only enter history; empty/whitespace-only do not).
- **Tab completion**: aware of CLI topology based on cursor position; completion candidates as shown:

| Cursor position | Completion content |
|---|---|
| Beginning of line / before `encrypt` subcommand | `encrypt` / `decrypt` / `list` / `help` / `?` / `h` / `quit` / `exit` / `q` |
| Positional arg after `help` / `?` / `h` | `encrypt` / `decrypt` / `list` |
| Any `--`-prefixed token after a subcommand | That subcommand's recognized long flags (e.g. `encrypt` additionally `--compress` / `--fast` / `--level` / `--chunk-size` / `--auto` / `--max-depth`; `decrypt` only additionally `--auto` / `--max-depth`; `list` only the common `--help` / `--lang` / `--no-color` / `--verbose` / `--quiet` / `--no-safe` / `--password-file` / `--password-env-var` / `--jobs` / `--output-dir`) |
| Any single-`-`-prefixed token after a subcommand | Above long flags + common short flags (`-p` / `-j` / `-o` / `-h` / `-v` / `-q` / `-z` / `-pev`, short flags only) |
| Token after `--compress ` | `none` / `lz4` / `zstd` |
| Token after `--lang ` | `en` / `zh` |
| Any other position | readline default filename completion (fallback) |

When completing a `--xxx=value` token, it strips to `--xxx` then does prefix filtering. On unique match readline auto-completes and appends a space (`rl_completion_append_character = ' '`); on multiple candidates the first `Tab` rings the bell for ambiguity, and the second `Tab` lists all candidates — matching bash behavior. Flags like `--no-safe` are not rewritten by completion.

#### Compile-time dependency detection

`CMakeLists.txt` probes via `find_library(Readline_LIBRARY NAMES readline)` + `find_path(Readline_INCLUDE_DIR NAMES readline/readline.h)`; when both hit, it sets the cache var `LOCK_HAVE_READLINE=ON`, and exposes:

- `-DLOCK_HAVE_READLINE=1` to all lock TUs;
- `${Readline_LIBRARY}` (plus `${Readline_TINFO_LIBRARY}` when found, to prevent `-Wl,--as-needed` from dropping the transitive dep under ThinLTO) into `target_link_libraries(lock PRIVATE ...)`.

readline is not REQUIRED; if any one is missing it degrades: `LOCK_HAVE_READLINE=OFF`, build links `0`, `cli.cpp`'s `#if LOCK_HAVE_READLINE` branch follows the `std::getline` path, and on REPL startup prints a one-line `[repl] readline not found at build time — using line mode (no history, no Tab completion)` to STDERR (localized: Chinese build environments display the corresponding Chinese). The REPL has zero readline.h dependency — `include/lock/repl.hpp` doesn't proxy `readline.h`, only exposes two entry points: `repl_readline(prompt, out)` and `repl_install_completer()`; `src/repl.cpp` internally does `extern "C" { #include <readline/readline.h> #include <readline/history.h> }`.

After build, `ldd build/lock | grep readline` in an environment where libreadline was detected shows `libreadline.so.8` and `libtinfo.so.6`.

### Shell tab-completion

`lock --completion <shell>` generates, at runtime based on the CLI's known flag set, a shell completion script ready to `eval` / source, writes it to stdout, and exits with code 0. Supports bash, zsh, and fish; the script is assembled in-memory by the `lock` binary via pure C++ string concatenation — no external sub-process, no network request, no third-party completion library. The script text is fixed English (doesn't change with `--lang`) because the script is parsed by the shell, not read line-by-line by the end user.

To enable:

```bash
# bash — add to ~/.bashrc:
eval "$(lock --completion bash)"

# zsh: first ensure completion is enabled (usually already in .zshrc:
#      autoload -Uz compinit && compinit)
eval "$(lock --completion zsh)"
# Or copy the script to any fpath dir named _lock (command name + underscore prefix):
#   lock --completion zsh > ~/.zsh/_lock
#   fpath=(~/.zsh $fpath); autoload -Uz compinit && compinit

# fish: can source directly
lock --completion fish | source
```

Completion coverage:

- Subcommand names `encrypt` / `decrypt` / `list` auto-complete after `lock `.
- Each subcommand's short/long flags (e.g. `lock encrypt -<TAB>`, `lock decrypt --<TAB>`).
- `--compress <TAB>` completes `none` / `lz4` / `zstd`; `--lang <TAB>` completes `en` / `zh`.
- `-p` / `--password-file` completes files; `-o` / `--output-dir` / `--auto` completes directories; positional args fall through to the shell's default file completion.
- `list` subcommand **does not** complete `--compress` / `-z` / `--fast` / `--level` / `--auto` / `--max-depth` (encrypt-only flags).

`--completion` also accepts the `=` form: `lock --completion=bash` behaves identically to the space form. `--lang` / `--no-color` appearing before `--completion` are recognized (error messages localized to the selected language), but the script body is unaffected. Unrecognized shell names return non-zero exit code 2 and print a localized error to STDERR; stdout has no half-script:

```bash
$ lock --completion bogus; echo "rc=$?"
error: unsupported shell 'bogus' (choose: bash, zsh, fish)
rc=2
$ lock --completion; echo "rc=$?"
error: missing shell argument (use: bash|zsh|fish)
rc=2
```

If you use `make install` (CMake's `install` target), the build system invokes the freshly installed `lock` binary to generate the three scripts into the standard vendor paths under `${CMAKE_INSTALL_DATADIR}`:

| Shell | Install path |
|---|---|
| bash  | `${datadir}/bash-completion/completions/lock`               |
| zsh   | `${datadir}/zsh/site-functions/_lock`                       |
| fish  | `${datadir}/fish/vendor_completions.d/lock.fish`            |

So no `eval` is needed — the corresponding shell auto-loads them. The source tree doesn't keep any generated artifacts; installed scripts always reflect the current binary's actual flag topology.

## TUI Interface

`lock --tui` launches a full-screen terminal interface based on ftxui, providing menu-driven encrypt/decrypt flows.

```bash
lock --tui                # Launch TUI (Chinese or English depends on language detection)
lock --lang zh --tui      # Force Chinese-localized TUI
lock --lang en --tui      # Force English TUI
```

### TUI Guard Conditions

The TUI performs two checks before entering the menu; if either fails it exits with code 2 and prints an error to STDERR:

| Condition | Check | Failure message (English) |
|---|---|---|
| stdin + stderr must be a tty | `isatty(STDIN_FILENO) && isatty(STDERR_FILENO)` | `TUI mode requires an interactive terminal (tty)` |
| Color support must be enabled | `color_enabled()` (i.e. no `--no-color` / `NO_COLOR` / `CLICOLOR=0`) | `TUI mode requires color support (don't use --no-color or NO_COLOR)` |

Running non-tty (pipe/redirect/CI) auto-triggers the first rejection; `--no-color` triggers the second regardless of appearing before or after `--tui`.

### Mutual Exclusion with Other Top-level Flags

`--tui` is a "parallel top-level flag" alongside `--cli`, `--help`, `--version`, `<subcommand>` (`encrypt` / `decrypt` / `list`) — the first one appearing in argv wins; subsequent parallel flags are ignored. `--lang` coexists with `--tui` (affects TUI text language). `--completion` is handled at an earlier stage and doesn't conflict with `--tui`.

### Main Menu (4 items)

| Chinese | English | Action |
|---|---|---|
| 加密 (Encrypt) | Encrypt | ↑/↓ then Enter to enter the encrypt wizard (4 steps) |
| 解密 (Decrypt) | Decrypt | ↑/↓ then Enter to enter the decrypt wizard (3 steps) |
| 查看 (List) | List | ↑/↓ then Enter to enter the List file picker |
| 退出 (Quit) | Quit | Exit TUI, exit code 0 |

Default highlight is on the first item (Encrypt). Esc or selecting "Quit" terminates the entire TUI session; the other three **loop back to the main menu** after completing their wizard / picker (user can proceed to the next operation); only Quit truly closes the TUI.

### Wizard Multi-step Flow

Post Wave D the TUI splits each encrypt/decrypt operation into a multi-step wizard (no longer all-fields-on-one-screen), with a `[1/4] [2/4] [3/4] [4/4]` step pill bar at the top showing current progress:

```
        Encrypt —— fill fields then choose Finish
        [1/4]  [2/4]  [3/4]  [4/4]
        ──────────────────────────────
              Step 1/4: Select Files
        ──────────────────────────────
        [interaction area]
        ──────────────────────────────
          ← Back  Next →  Finish  Cancel
```

Each step's "Next" button first runs that step's field validation; on failure it shows a red error below the interaction area and stays on the current step; only on validation pass does it advance. On the last step (password), "Next" becomes "Finish" per the writing policy: "always show 4 buttons, the Next button is disabled and grayed out on the last step, the user presses Finish to trigger the actual encrypt/decrypt". Esc or "Cancel" exits the wizard **back to the main menu** (not the entire TUI session) at any step.

On completion, the wizard returns to the main menu (user can proceed to the next operation); Quit/Esc remains the only entry that truly closes the TUI.

### File Browser

Step 0 and the List picker reuse the same file browser component. Each row's format:

| Prefix | Meaning |
|---|---|
| `[ ]` | Not selected |
| `[*]` | File selected (user pressed Space on it) |
| `[-]` | Directory — at least one descendant file is selected (partial selection) |

Directory prefixes always show `[ ]` or `[-]`; directories themselves cannot be "selected" (only entered). Directory listing sort order: `..` always at the top (except in root), then directories before files, ascending alphabetical.

| Key | Action |
|---|---|
| ↑ / ↓ | Move cursor in file list |
| Enter | On a directory, enter it; on `..`, go back to parent |
| Space | On a file, toggle selected/unselected |
| Tab / Tab+Shift | Switch focus between the interaction area and the bottom button row (step 0 only intercept, see below) |

"Unsafe" entries (symlinks, special files, sockets etc.) are auto-skipped; when `only_dot_locked` is true, the list shows only `.locked`-suffixed regular files, narrowing the candidate set for the decrypt wizard / List picker.

### Tab Focus Interception (step 0)

Step 0's interaction area (file browser) is inside the top-level step_stack container; the bottom buttons row is a sibling component. Wave D manually intercepts `Event::Tab`/`Event::TabReverse` in the wizard's CatchEvent layer:

- When focus is inside step_stack and current step = 0, Tab → move focus to buttons row (so the user can reach "Next" with Tab+Tab without traversing all file browser entries first)
- When focus is on buttons row, Tab+Shift → move focus back to step_stack

Other steps (1/2/3) have regular Input/Button combinations; Tab behavior follows ftxui's default container navigation.

### Encrypt Wizard — 4 Steps

| Step | Title | Fields |
|---|---|---|
| 1/4 | Select files | File browser (Space to select, Enter to enter dir, `..` to go back) |
| 2/4 | Compression params | No compression / `lz4 (fast)` / `zstd (balanced)` three Buttons (mutually exclusive Radio); compression level Input (zstd 1..22, disabled and dimmed for other algos) |
| 3/4 | Output & concurrency | Output dir Input (empty = same dir as input); concurrency Input (0 = auto-recommended) |
| 4/4 | Password | Password Input (hidden); confirm password Input (hidden) |

Per-step validation rules:

| Step | Validation |
|---|---|
| 1 | At least one file selected (`bs.selected` non-empty) |
| 2 | None (zstd level verified 1..22 by `validate_encrypt_step_compress`) |
| 3 | None |
| 4 | Password non-empty; matches confirm password |

After all pass, pressing "Finish" makes the wizard return to the main menu while the entire TUI exits alt-screen; `run_encrypt` executes in the normal terminal (`cout` / `cerr` / progress bar direct to user); on completion prints a result line, prompts "press enter to return to main menu", waits for input, then returns to the main menu.

### Decrypt Wizard — 3 Steps

| Step | Title | Fields |
|---|---|---|
| 1/3 | Select .locked files | File browser (lists only `.locked` regular files) |
| 2/3 | Output & concurrency | Output dir Input; concurrency Input (0 = auto-recommended) |
| 3/3 | Password | Password Input (hidden) (decrypt has no confirm-password field) |

Validation:

| Step | Validation |
|---|---|
| 1 | At least one `.locked` file selected |
| 2 | None |
| 3 | Password non-empty |

Post-completion flow is identical to Encrypt: exit alt-screen → `run_decrypt` executes → print result → Enter → main menu.

### List Picker

"List" is no longer a placeholder card: it opens an independent file browser (lists only `.locked` files); the bottom "List" button executes `run_list` to print metadata; the "Cancel" button returns to the main menu. Esc inside the picker also returns to the main menu.

### Password Handling

ftxui's `Input` component, with `password=true` set, hides character display — no echo to the terminal line. After the user fills in the password in wizard step 4 (Encrypt) or step 3 (Decrypt), "Finish" triggers `execute_encrypt` / `execute_decrypt`: creates a temp file via `mkstemp`, writes the plaintext password, then calls `run_encrypt` / `run_decrypt` in `PasswordMode::FromFile` + `--no-safe` mode. After encryption/decryption completes, the temp file is immediately zeroed and `unlink`ed, preventing disk residue.

### Keyboard Operation (main menu / wizard / picker common)

| Key | Main menu | Wizard interaction area | Wizard button row | List picker |
|---|---|---|---|---|
| ↑ / ↓ | Move between menu items | Move in file browser list | (no-op) | Move in file browser list |
| Enter | Select to enter corresponding wizard / picker | Enter dir / trigger on_enter | Trigger current button | Enter dir |
| Space | (no-op) | Toggle file selection | (no-op) | Toggle file selection |
| Tab | (no-op) | Switch to buttons row (step 0) / in-component navigation (other steps) | Tab+Shift back to step_stack (step 0); Tab to next button | (no-op) |
| Esc | Exit TUI (rc=0) | Exit wizard to main menu | Exit wizard to main menu | Exit picker to main menu |

### Cross-platform & Dependencies

ftxui is auto-fetched via CMake FetchContent, same as lz4 and zstd. First `cmake --preset default` downloads ftxui source from GitHub and compiles it as a static lib, statically linked with `lock`. `lock --tui` is only available on platforms with POSIX termios (Linux / macOS).

## Three Password Sources

| Mode | Usage | Safety guardrail |
|---|---|---|
| Interactive (default) | `lock encrypt foo.txt`, then prompt | None (safe) |
| File | `lock encrypt -p ./pw.txt --no-safe foo.txt` | **requires** `--no-safe` |
| Env var | `LOCK_PASSWORD=xxx lock encrypt --password-env-var --no-safe foo.txt` | **requires** `--no-safe` |

`--password-env-var` can be abbreviated as `-pev`.

Without `--no-safe`, reading passwords from file/env is rejected with an error, avoiding fsync journal, core dump, process list leaks.

## Full Options List

```
Commands:
  encrypt    encrypt one or more files into .locked containers
  decrypt    decrypt one or more .locked containers
  list       print .locked container metadata (no decryption)

Options:
  -p, --password-file <path>   read passphrase from file (requires --no-safe)
      --password-env-var       read passphrase from $LOCK_PASSWORD (requires --no-safe)
      --no-safe                confirm use of unsafe passphrase sources
  -j, --jobs <N>                worker threads per file (default: hardware_concurrency)
  -o, --output-dir <dir>        output directory (default: same dir as input)
      --chunk-size <bytes>      encryption chunk size (default: 1 MiB; must be ≥4096 and a multiple of 16)
  -z                            Shorthand for --compress zstd (balanced compression)
      --compress <algo>          Compress before encrypt: none|lz4|zstd (default: none)
      --fast                     Shorthand for --compress lz4 (fast, low ratio)
      --level <N>                Compression level: zstd 1..22 (default 3); lz4 ignores
  -v, --verbose                 extra status to stderr
  -q, --quiet                   disable progress bar (errors still print)
      --lang <en|zh>            override language detection; can appear anywhere on the command line
      --no-color                disable colors and progress bar ANSI cursor control (NO_COLOR / CLICOLOR=0 also apply)
      --version                 print version
  -h, --help                    print help
```

## Encrypted File Format (`.locked`)

```
+────────────────+──────────────────────────────────────+
│ Fixed Header   │ v1: 112 bytes; v2: 124 bytes          |
+────────────────+──────────────────────────────────────+
│ Encrypted      │ filename_len bytes                   │
│ Filename       │                                      │
+────────────────+──────────────────────────────────────+
│ Tag Length      │ 4 bytes (be32 = 16)                 |
+────────────────+──────────────────────────────────────+
│ Filename Tag   │ 16 bytes (AES-256-GCM tag)           │
+────────────────+──────────────────────────────────────+
│ Ciphertext     │ v1: original_size bytes              │
│ Region         │ v2: sum of per-chunk compressed CT   │
+────────────────+──────────────────────────────────────+
│ Offset Table   │ v2 only: chunk_count × 4 bytes (be32)│
+────────────────+──────────────────────────────────────+
│ HMAC Footer    │ 32 bytes (HMAC-SHA256)              │
+────────────────+──────────────────────────────────────+
```

### Fixed Header (124 bytes, big-endian)

| Offset | Length | Field | Description |
|---:|---:|---|---|
| 0   | 16 | `magic`        | `ENCF0001v1\0\0\0\0\0\0` |
| 16  | 4  | `version`      | `1` |
| 20  | 4  | `algorithm_id` | `0x02` = `AES_256_CTR_HMAC_SHA256` |
| 24  | 4  | `kdf_id`       | `0x02` = `SCRYPT` |
| 28  | 4  | `kdf_N`        | `16384` (N=2^14) |
| 32  | 4  | `kdf_r`        | `8` |
| 36  | 4  | `kdf_p`        | `1` |
| 40  | 32 | `salt`         | random salt |
| 72  | 16 | `base_iv`      | random IV base |
| 88  | 4  | `flags`        | `0x01` = filename present |
| 92  | 4  | `filename_len` | encrypted filename byte count |
| 96  | 8  | `original_size`| original file byte count |
| 104 | 4  | `chunk_size`   | chunk size (default 1 MiB) |
| 108 | 4  | `chunk_count`  | total chunk count |
| 112 | 4  | `compression_id` | v2 field; `0` = NONE / `1` = LZ4 / `2` = ZSTD (v1 files read as NONE) |
| 116 | 8  | `stored_size`  | v2 field; total bytes of ciphertext region + offset table (v1 files read = `original_size`) |

> v1 files don't have the bytes at offset 112 / 116; these are v2 additions. On read, HeaderReader auto-normalizes: treats v1 as `compression_id=NONE`, `stored_size=original_size`, so the decrypt path is consistent across v1/v2. The write path always outputs v2.

## Encryption Design

### Key Derivation

```
scrypt(password, salt, N=16384, r=8, p=1, maxmem=64 MiB) → 64 bytes
  ├─ bytes [0..31]  → file_key  (AES-256 key)
  └─ bytes [32..63] → hmac_key  (HMAC-SHA256 key)
```

Each file uses an independent random `salt` (32 bytes) and `base_iv` (16 bytes), both generated by `RAND_bytes`.

### Filename Encryption (AES-256-GCM)

- **Key**: `file_key`
- **Nonce**: `SHA-256(file_key)[0..11]` (12 bytes, deterministic, safe because each file has a distinct file_key)
- **AAD**: `SHA-256(magic || version_be32 || algorithm_id_be32 || salt || base_iv || original_size_be64)`
- **Plaintext**: original filename byte sequence
- **Tag**: 16-byte GCM tag, stored in the header

AAD binds the header's fixed fields so any header tampering causes GCM verification to fail on decrypt.

### Content Encryption (AES-256-CTR)

Each chunk's IV is derived from `base_iv` (gocryptfs mode):

```
chunk_iv = base_iv
chunk_iv[8..15] (low 64 bits) = big-endian( base_counter + block_offset )

# where block_offset = (chunk_index × chunk_size) / AES_BLOCK_SIZE
```

The high 64 bits are a per-file random nonce, guaranteeing distinct IVs across multiple encryptions of the same file with the same passphrase; the low 64 bits are a block counter, guaranteeing no IV reuse across chunks within the same file.

CTR mode is symmetric; the same function handles both encrypt and decrypt. Multi-threading dispatches all chunks to a fixed thread pool; each thread has its own `EVP_CIPHER_CTX` (OpenSSL contexts are not thread-safe).

### Content Compression (LZ4 / zstd)

Each chunk is first compressed with LZ4 or zstd, then encrypted with AES-256-CTR; both compression and encryption run in parallel in worker threads.

v2 file layout: each chunk's compressed CT is variable-length; the file's tail has an offset table recording each chunk's compressed size (be32 × chunk_count). HMAC covers `header_serialised || chunk CT || offset_table`; v1 has no offset table — HMAC covers only `header_serialised || ct`. On decryption the reader decides whether to include the offset table in the HMAC based on the version field.

IV derivation changed to `derive_chunk_iv_v2`: high 64 bits = base_iv[0..7] XOR be64(chunk_index); low 64 bits = base_counter + (accumulated CT byte count / 16). This guarantees both per-chunk independent IVs and monotonically increasing counters for variable-length chunks. The v1 formula `derive_chunk_iv(base_iv, i * chunk_size / AES_BLOCK_SIZE)` applies to equal-length chunks.

Security argument: compress-then-encrypt is safe for static file encryption (cf. 7z / ZFS / OpenPGP); CRIME/BREACH-class attacks require an interactive chosen-plaintext oracle, which static file encryption doesn't constitute. The only residual info leak is "compression ratio itself leaks file type/entropy", low-risk for normal users.

Even with `--compress none` (or unspecified), v2 still writes an offset table (single decrypt path); v1 files are readable but no longer written.

### Integrity Authentication (HMAC-SHA256)

```
mac = HMAC-SHA256(hmac_key, header_serialised || chunk CT || offset_table)
```

The 32-byte HMAC is written at the file's tail. v2's HMAC covers `header_serialised || chunk CT || offset_table`; v1 has no offset table — HMAC covers only `header_serialised || ct`. On decrypt, the HMAC is recomputed in the same order and compared with a constant-time comparison (`CRYPTO_memcmp`); v1/v2 is auto-distinguished by the version field. Any header/ciphertext/offset-table tampering is detected.

## Streaming I/O & Memory Model

v2 replaces the legacy "load entire file into memory" model with a streaming chunk pipeline, decoupling peak memory from file size.

### Encrypt Stream

```
reader (single-threaded sequential read) → N× compress worker (parallel, -j) → encrypt-then-write (single-threaded, serial)
                                                                        ↓
                                                               ofstream + streaming HMAC
                                                                        ↓
                                                           write offset_table → HMAC → 32B footer
```

- reader single-threaded sequential read from source file
- N compress workers (controlled by `-j`) do LZ4/zstd compression in parallel
- Single-threaded encrypt + write runs serially: because v2's `derive_chunk_iv_v2` needs the accumulated CT size of preceding chunks to compute the current IV
- ofs streaming `HMAC.update(ct_chunk)` while writing ofstream
- After all chunks are processed, write the offset_table sequentially, update HMAC with it, then write the 32-byte footer

### Decrypt Stream

```
reader (header + offset_table) → N× decrypt+decompress (parallel, -j) → single-threaded sequential write to .lockdec.tmp
                                                                              ↓
                                                                       streaming HMAC
                                                                              ↓
                                                              EOF → compare footer → rename / unlink
```

- reader reads header and offset_table, gets per-chunk ciphertext offsets
- N workers (controlled by `-j`) do CTR decrypt + decompress in parallel
- Single-threaded sequential write of plaintext to `.lockdec.tmp` temp file in the same dir as the output (same filesystem, ensuring `rename(2)` is atomic)
- Streaming `HMAC.update` simultaneously
- After EOF, compare HMAC footer: on match `rename(2)` atomically replaces to final path; on mismatch `unlink` the temp file and error out

### Peak Memory

```
peak_memory = O((N + 1) × chunk_size)
```

Completely independent of file size. Each worker holds roughly one chunk's buffer; the single-threaded write end also holds one chunk. Suitable for encrypting GB-scale files.

### Auto-tuning

When the user doesn't explicitly specify `--chunk-size` or `-j`, the `memory` module auto-recommends based on available memory:

- Linux: `sysconf(_SC_AVPHYS_PAGES)`
- macOS: `sysctl` family calls
- Both fail: fallback to conservative values (512 MiB available / 1 GiB chunk budget)

Recommended value clamp rules:
- `chunk_size`: `[256 KiB, 4 MiB]`, must be a multiple of 16
- `jobs`: `[1, hardware_concurrency]`, reserving roughly `4 × chunk_size` bytes per worker

The user can override via explicit `--chunk-size <bytes>` or `-j <N>`; `-v` prints the actually-used values to stderr:

```
[memory] available=2048 MiB; chunk_size=1024 KiB; jobs=4
```

### `.tmp` File Convention

The decrypt temp file is named `<output>.lockdec.tmp`, in the same dir as the final artifact (same filesystem), ensuring `rename(2)` is atomic.

- Normal completion (HMAC pass): `rename(2)` .tmp → final path
- HMAC failure or decrypt interruption: `unlink` cleans up .tmp
- Abnormal process exit (SIGKILL, system crash): .tmp file residue requires manual cleanup (no pid/lock-file mechanism)

## Project Structure

```
.
├── CMakeLists.txt           # build config (FetchContent lz4/zstd/ftxui, ThinLTO, LLD)
├── CMakePresets.json        # presets: default / debug / aarch64-static
├── cmake/
│   └── aarch64-linux-gnu.cmake  # aarch64 cross toolchain (-static-pie, multiarch .a)
├── .clang-format
├── include/lock/
│   ├── constants.hpp        # file format constants, scrypt default params
│   ├── endian.hpp           # big-endian load/store helpers
│   ├── errors.hpp           # ExitCode enum + custom exception classes
│   ├── kdf.hpp              # scrypt KDF interface
│   ├── crypto.hpp           # encrypt/decrypt interface (AES-256-CTR / GCM, IV derivation)
│   ├── compress.hpp         # compression interface (LZ4 / zstd)
│   ├── container.hpp        # FileHeader struct + HeaderWriter/Reader
│   ├── memory.hpp           # available memory detection + chunk_size/jobs auto-recommend
│   ├── progress.hpp         # progress bar wrapper (hand-written ASCII renderer)
│   ├── safe.hpp             # three password-source modes (interactive / file / env)
│   ├── term.hpp             # termios ECHO toggle
│   ├── i18n.hpp             # Lang/Str enums + tr() table-driven localization
│   ├── cli.hpp              # cli_main() entry
│   ├── cli_dispatch.hpp     # subcommand dispatch (encrypt/decrypt/list) + prompt strings
│   ├── completion.hpp       # `--completion <shell>` outputs bash/zsh/fish scripts
│   ├── repl.hpp            # `--cli` REPL entry (readline / getline fallback)
│   └── tui.hpp             # `--tui` entry (ftxui wizard / file browser)
├── src/
│   ├── main.cpp             # 1-line delegate: `return lock::cli_main(argc, argv);`
│   ├── kdf.cpp              # scrypt via EVP_KDF (OpenSSL 3.x)
│   ├── crypto.cpp           # AES-256-CTR parallel + AES-256-GCM filename
│   ├── compress.cpp         # LZ4/zstd block-API compression wrapper
│   ├── container.cpp        # header serialize/deserialize + v1/v2 compat
│   ├── memory.cpp           # sysconf/sysctl available-memory detection + tuning
│   ├── progress.cpp         # hand-written progress bar renderer (per-file + overall, ASCII `[=====>]`)
│   ├── safe.cpp             # password input handling (getpass / file / env)
│   ├── term.cpp             # termios wrapper
│   ├── i18n.cpp             # Lang/Str table + `tr()` impl + detection logic
│   ├── cli.cpp              # positional arg parsing + top-level dispatch
│   ├── cli_dispatch.cpp     # subcommand impl (encrypt/decrypt/list/auto batch)
│   ├── completion.cpp       # bash/zsh/fish completion script assembly
│   ├── repl.cpp             # readline integration + Tab completer
│   └── tui.cpp              # ftxui main menu + multi-step wizard + file browser
├── scripts/
│   └── smoke-tui.sh         # TUI smoke test (8 steps)
├── dist/arch/{x86_64,aarch64}/lock  # artifact copies (gitignore the binary; keep dir placeholders)
├── build/                   # default preset output (gitignore)
└── build-aarch64/           # aarch64-static preset output (gitignore)
```

## Security Notes

- No "forward secrecy"; passphrase strength is everything — recommend ≥ 12 mixed characters
- Reading passphrases from file/env is disabled by default: filesystem journals, core dumps, `/proc/<pid>/environ` can all leak
- On decryption, the plaintext is first written to `.lockdec.tmp` temp file in the same dir as the output, streaming HMAC while decrypting; after all chunks complete and HMAC matches the footer, `rename(2)` atomically replaces to the final path; on mismatch `unlink` the temp file and error out. Temp `.tmp` files left by abnormal process exit are not treated as formal artifacts (also cleaned up if crash happens before HMAC comparison)
- `RAND_bytes` comes from OpenSSL's default random source (getrandom/CSPRNG)
- No key rotation / multi-recipient / key escrow; suitable for personal file encryption

## Cross-arch Artifacts (`dist/arch/`)

Cross-compile a **single static-pie binary** for aarch64 Linux on an x86_64 host via `cmake --preset aarch64-static`. Both architectures' artifacts can coexist at `dist/arch/<arch>/lock`:

```
dist/
└── arch/
    ├── x86_64/lock        ← output of cmake --preset default (dynamic)
    └── aarch64/lock       ← output of cmake --preset aarch64-static (full static)
```

| Arch | Preset | Linking | Size | Runtime deps |
|---|---|---|---|---|
| x86_64  | `default`        | dynamic (OpenSSL / readline / glibc / libstdc++) | ~1.7 MB | target needs same OpenSSL 3.x / readline |
| aarch64 | `aarch64-static` | full static (`-static-pie`), no `NEEDED` entries | ~11 MB | none — copy and run |

### Supported Range

- **x86_64 artifact**: standard x86_64 Linux (glibc 2.31+, OpenSSL 3.x). Tested on Debian/Ubuntu/RHEL/Fedora etc.
- **aarch64 artifact**: standard aarch64 Linux (glibc 2.31+), **including but not limited to**:

  - Debian/Ubuntu/Raspberry Pi OS 64-bit / Alpine aarch64 glibc variants / any aarch64 Linux distro
  - Raspberry Pi 4/5 (aarch64 Raspberry Pi OS)
  - aarch64 servers / cloud instances / embedded Linux boards (glibc 2.31+ required)

### Unsupported Platforms — Termux / Android

`dist/arch/aarch64/lock` **cannot run on Termux / Android**. This is not a toolchain-parameter limitation but a fundamental architecture mismatch between glibc and Bionic:

1. Our arm64 binary statically links **glibc**; its `_start` calls glibc's `__libc_start_main` bootstrap (application of RELA relocations, TLS initialization, running preinit arrays, etc.).
2. Android since 5.0 routes `e_type=DYN` (PIE) binaries to Bionic's `linker64`. `linker64` does the same execution-environment setup before jumping to `_start` (applies RELA relocations itself, initializes Bionic TLS, runs `DT_INIT_ARRAY` constructors).
3. Then `linker64` jumps to the binary's `_start`; glibc's bootstrap does a second round of relocations / TLS initialization, conflicting with Bionic's already-done state → the process immediately segfaults (in user scenarios `lock --help` segfaults directly with no error message).

Earlier work to make the binary pass Bionic's two hard boundary checks (commit `9cd5813`'s `-static-pie` to set e_type=DYN; commit `3bbf66e`'s alignas(64) thread_local dummy variable to bump PT_TLS p_align to 64) resolved Bionic's "PIE-only" and "TLS alignment 64" rejections, but not the subsequent glibc/Bionic dual-libc mutual exclusion.

To run `lock` on Termux/Android, you'd need to cross-build a native Bionic binary using the Android NDK, or compile directly inside Termux with `clang++` — both are separate build paths not included in the current presets.

## Limitations

- After the v2 streaming rewrite, peak memory is independent of file size, fixed at `O((N+1) × chunk_size)`; there's no 64 GiB hard upper limit (and MAX_PLAINTEXT_BYTES is no longer set)
- No support for incremental encryption, streaming stdin/stdout
- v2 format is production-ready; v1 files are read-only compatible (auto-normalized by HeaderReader); the write path always outputs v2
- Compression ratio leaks some file info (type/entropy); for highly sensitive scenarios use `--compress none`
- Only Linux/macOS tested (depends on POSIX termios)
- The aarch64 cross-compile artifact (`dist/arch/aarch64/lock`) supports standard glibc aarch64 Linux; does not support Termux / Android (glibc and Bionic dual-libc cannot coexist — see "Unsupported platforms" above)

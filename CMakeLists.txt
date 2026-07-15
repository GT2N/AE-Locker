cmake_minimum_required(VERSION 3.25)

# Default to Ninja if no generator was selected by the caller.
if(NOT CMAKE_GENERATOR)
    set(CMAKE_GENERATOR Ninja CACHE STRING "Build generator" FORCE)
endif()

project(lock LANGUAGES C CXX VERSION 1.0.0)

# -----------------------------------------------------------------------------
# Compiler guard: require Clang.
# -----------------------------------------------------------------------------
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR
        "The 'lock' project requires the Clang C/C++ compiler.\n"
        "Detected CMAKE_CXX_COMPILER_ID='${CMAKE_CXX_COMPILER_ID}'.\n"
        "Install Clang on Debian/Ubuntu with:\n"
        "    sudo apt-get install clang lld\n"
        "and re-run with -DCMAKE_C_COMPILER=clang "
        "-DCMAKE_CXX_COMPILER=clang++")
endif()

# -----------------------------------------------------------------------------
# Require Clang >= 15.
# -----------------------------------------------------------------------------
if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 15)
    message(FATAL_ERROR
        "Clang >= 15 is required (detected ${CMAKE_CXX_COMPILER_VERSION}).\n"
        "On Debian/Ubuntu:\n"
        "    sudo apt-get install clang-15 lld-15")
endif()

# -----------------------------------------------------------------------------
# C++20 standard.
# -----------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# -----------------------------------------------------------------------------
# Modules: CheckCXXCompilerFlag and CheckLinkerFlag.
# -----------------------------------------------------------------------------
include(CheckCXXCompilerFlag)
include(CheckLinkerFlag)
include(FindPackageHandleStandardArgs)

# NOTE: Ordering is deliberate. All find_package / try-compile checks are done
# BEFORE we mutate CMAKE_C_FLAGS / CMAKE_CXX_FLAGS / linker flags with the
# ThinLTO and LLD options. Setting -flto=thin globally first would poison the
# Threads try-compile test and cause `find_package(Threads)` to fail.

# -----------------------------------------------------------------------------
# Threads (use the imported target Threads::Threads).
# -----------------------------------------------------------------------------
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# -----------------------------------------------------------------------------
# OpenSSL 3.x.
# -----------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)

# -----------------------------------------------------------------------------
# GNU readline (optional).
#
# Probe for libreadline and its dev headers. When both are available we set
# CACHE var `LOCK_HAVE_READLINE=ON` so downstream `target_compile_definitions`
# can advertise `LOCK_HAVE_READLINE=1` to translation units; otherwise the
# cache var stays OFF and cli.cpp falls back to `std::getline` (no history,
# no Tab completion). The dependency is strictly soft — `cmake --preset
# default` succeeds either way.
#
# We deliberately do NOT use `find_package(readline)` because the standard
# modules shipped with CMake never include a `FindReadline` module; a manual
# `find_library` + `find_path` pair is the canonical pattern.
# -----------------------------------------------------------------------------
find_library(Readline_LIBRARY NAMES readline)
find_path(Readline_INCLUDE_DIR NAMES readline/readline.h)
find_package_handle_standard_args(Readline
    REQUIRED_VARS Readline_LIBRARY Readline_INCLUDE_DIR)
# libtinfo (or ncurses on systems without it) is libreadline's only runtime
# companion; linking against it explicitly keeps -Wl,--as-needed from dropping
# the transitive dependency under -flto=thin.
find_library(Readline_TINFO_LIBRARY NAMES tinfo ncurses)
if(Readline_FOUND)
    set(LOCK_HAVE_READLINE ON CACHE BOOL "GNU readline available" FORCE)
else()
    set(LOCK_HAVE_READLINE OFF CACHE BOOL "GNU readline available" FORCE)
endif()
message(STATUS "lock: readline library -- ${Readline_LIBRARY}")
message(STATUS "lock: readline include -- ${Readline_INCLUDE_DIR}")
message(STATUS "lock: readline tinfo  -- ${Readline_TINFO_LIBRARY}")
message(STATUS "lock: GNU readline detected (LOCK_HAVE_READLINE=${LOCK_HAVE_READLINE})")

# -----------------------------------------------------------------------------
# Force the LLD linker.
# -----------------------------------------------------------------------------
find_program(LLD_PATH NAMES ld.lld)
if(NOT LLD_PATH)
    message(FATAL_ERROR
        "The LLD linker ('ld.lld') was not found on PATH.\n"
        "On Debian/Ubuntu:\n"
        "    sudo apt-get install lld")
endif()

string(APPEND CMAKE_EXE_LINKER_FLAGS    " --ld-path=${LLD_PATH} -fuse-ld=lld")
string(APPEND CMAKE_SHARED_LINKER_FLAGS " --ld-path=${LLD_PATH} -fuse-ld=lld")
string(APPEND CMAKE_MODULE_LINKER_FLAGS " --ld-path=${LLD_PATH} -fuse-ld=lld")

# -----------------------------------------------------------------------------
# ThinLTO.
# -----------------------------------------------------------------------------
option(ENABLE_THINLTO "Enable Clang ThinLTO" ON)

if(ENABLE_THINLTO)
    string(APPEND CMAKE_C_FLAGS   " -flto=thin")
    string(APPEND CMAKE_CXX_FLAGS " -flto=thin")

    string(APPEND CMAKE_EXE_LINKER_FLAGS    " -flto=thin -Wl,--lto-whole-program-visibility")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -flto=thin -Wl,--lto-whole-program-visibility")
    string(APPEND CMAKE_MODULE_LINKER_FLAGS " -flto=thin -Wl,--lto-whole-program-visibility")

    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/.lto-cache")
    # LLD (not gold) does not accept the `-plugin-opt=cache-dir=...` syntax
    # that gold uses.  Use LLD's native `--thinlto-cache-dir=` instead.
    string(APPEND CMAKE_EXE_LINKER_FLAGS
        " -Wl,--thinlto-cache-dir=${CMAKE_BINARY_DIR}/.lto-cache")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS
        " -Wl,--thinlto-cache-dir=${CMAKE_BINARY_DIR}/.lto-cache")
    string(APPEND CMAKE_MODULE_LINKER_FLAGS
        " -Wl,--thinlto-cache-dir=${CMAKE_BINARY_DIR}/.lto-cache")
endif()

# NOTE: libstdc++ is the default on this system. libc++ is NOT installed,
# so we intentionally do NOT add `-stdlib=libc++` here.

# -----------------------------------------------------------------------------
# indicators (header-only) via FetchContent.
# -----------------------------------------------------------------------------
include(FetchContent)
FetchContent_Declare(
    indicators
    GIT_REPOSITORY https://github.com/p-ranav/indicators.git
    GIT_TAG        v2.3
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(indicators)

# -----------------------------------------------------------------------------
# lz4 v1.9.4 (static) via FetchContent.
# -----------------------------------------------------------------------------
FetchContent_Declare(
    lz4
    GIT_REPOSITORY https://github.com/lz4/lz4.git
    GIT_TAG        v1.9.4
    GIT_SHALLOW    TRUE
    SOURCE_SUBDIR  build/cmake
)
set(LZ4_BUILD_CLI          OFF CACHE BOOL "" FORCE)
set(LZ4_BUILD_LEGACY_LZ4C  OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(lz4)
# lz4 v1.9.4's CMakeLists.txt defines `lz4_static` and `lz4_shared` (not a
# bare `lz4` target), and exposes no `lz4::lz4` alias until v1.10.0.  Under
# FetchContent the project is bundled, so BUILD_SHARED_LIBS defaults OFF and
# BUILD_STATIC_LIBS defaults ON -- only `lz4_static` is created.  Create the
# namespaced alias against `lz4_static` so consumers can link `lz4::lz4`.
if(NOT TARGET lz4::lz4)
    add_library(lz4::lz4 ALIAS lz4_static)
endif()

# -----------------------------------------------------------------------------
# zstd v1.5.7 (static) via FetchContent.
# -----------------------------------------------------------------------------
FetchContent_Declare(
    zstd
    URL https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz
    SOURCE_SUBDIR build/cmake
)
set(ZSTD_BUILD_STATIC    ON  CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED    OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_PROGRAMS  OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_CONTRIB   OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS     OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zstd)
# The static lib target produced by zstd's CMake is `libzstd_static`.  It does
# NOT define a `zstd::zstd` alias, so we link directly to `libzstd_static`.

# -----------------------------------------------------------------------------
# ftxui v5.0.0 via FetchContent.
#
# C++ TUI library (https://github.com/ArthurSonzogni/FTXUI). The repo owner's
# handle is `ArthurSonzogni` (with a `g`); the project exposes the canonical
# CMake targets `ftxui::component`, `ftxui::dom`, `ftxui::screen`, and the
# umbrella `ftxui::ftxui`. We pin GIT_TAG v5.0.0 (the version documented in
# the README). GIT_SHALLOW keeps the clone minimal.
# -----------------------------------------------------------------------------
FetchContent_Declare(
    ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
    GIT_TAG        v5.0.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(ftxui)

# -----------------------------------------------------------------------------
# Export compile commands for clangd / IDE tooling.
# -----------------------------------------------------------------------------
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# -----------------------------------------------------------------------------
# Status messages.
# -----------------------------------------------------------------------------
message(STATUS "lock: LLD linker path -- ${LLD_PATH}")
message(STATUS "lock: ThinLTO enabled -- ${ENABLE_THINLTO}")
message(STATUS "lock: OpenSSL version -- ${OPENSSL_VERSION}")

# -----------------------------------------------------------------------------
# Executable target.
#
# Sources will be added by another agent. To keep `cmake --preset default`
# working even when the sources are not yet present, we only declare the
# executable when src/main.cpp exists.
# -----------------------------------------------------------------------------
set(LOCK_SOURCES
    src/main.cpp
    src/cli.cpp
    src/completion.cpp
    src/crypto.cpp
    src/compress.cpp
    src/container.cpp
    src/memory.cpp
    src/kdf.cpp
    src/progress.cpp
    src/safe.cpp
    src/term.cpp
    src/i18n.cpp
    src/repl.cpp
    src/tui.cpp
)

if(EXISTS "${CMAKE_SOURCE_DIR}/src/main.cpp")
    add_executable(lock ${LOCK_SOURCES})

    # indicators is header-only; we consume it via a SYSTEM include directory
    # (see target_include_directories below) so that its internal warnings are
    # suppressed under our strict -Werror/-Wconversion flags.  We do NOT link
    # the `indicators::indicators` target because its INTERFACE include
    # directory is non-SYSTEM and would re-enable warnings on indicators code.
    target_link_libraries(lock PRIVATE
        Threads::Threads
        OpenSSL::Crypto
        OpenSSL::SSL
        lz4::lz4
        libzstd_static
        ftxui::component
    )

    target_compile_features(lock PRIVATE cxx_std_20)

    # indicators and ftxui are third-party libraries whose code produces
    # numerous warnings under our strict -Werror -Wconversion -Wsign-conversion
    # flags.  Mark their include directories SYSTEM (-isystem) so warnings
    # emitted from inside these headers are suppressed entirely.  We do NOT
    # link `indicators::indicators` for the same reason — its INTERFACE
    # include directory is non-SYSTEM and would re-enable warnings on
    # indicators code.  `ftxui::component` is safe to link directly because
    # its target-level include dir is PRIVATE, but we still mirror the SYSTEM
    # pattern below to suppress ftxui's own internal header warnings.
    target_include_directories(lock SYSTEM PRIVATE
        ${indicators_SOURCE_DIR}/include
        ${lz4_SOURCE_DIR}/lib             # for lz4.h (lz4 path is ../lib)
        ${zstd_SOURCE_DIR}/lib            # for zstd.h
        ${ftxui_SOURCE_DIR}/include       # ftxui public headers
    )

    target_include_directories(lock PRIVATE
        ${CMAKE_SOURCE_DIR}/include
    )

    target_compile_options(lock PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -Wconversion
        -Wshadow
    )

    # -------------------------------------------------------------------------
    # GNU readline linkage (conditional on LOCK_HAVE_READLINE).
    #
    # When readline is present, advertise `LOCK_HAVE_READLINE=1` to every TU so
    # cli.cpp's `#if LOCK_HAVE_READLINE` branch compiles in the readline-based
    # REPL; otherwise advertise `=0` and leave cli.cpp with std::getline.
    # -------------------------------------------------------------------------
    if(LOCK_HAVE_READLINE)
        target_compile_definitions(lock PRIVATE LOCK_HAVE_READLINE=1)
        target_link_libraries(lock PRIVATE ${Readline_LIBRARY})
        if(Readline_TINFO_LIBRARY)
            target_link_libraries(lock PRIVATE ${Readline_TINFO_LIBRARY})
        endif()
    else()
        target_compile_definitions(lock PRIVATE LOCK_HAVE_READLINE=0)
    endif()

    install(TARGETS lock RUNTIME DESTINATION bin)

    # -------------------------------------------------------------------------
    # Shell tab-completion scripts.  Generated at install time by invoking the
    # freshly-built `lock` binary (`lock --completion <shell>`) — the source
    # tree therefore stays free of generated artefacts and the installed
    # scripts never drift from the binary's actual flag set.  Destinations
    # follow each shell's vendor convention so a default `DESTDIR`+`make
    # install` makes completion work with zero extra user setup.
    # -------------------------------------------------------------------------
    include(GNUInstallDirs)
    install(CODE "
        set(LOCK_BIN \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/\${CMAKE_INSTALL_BINDIR}/lock\")
        if(NOT EXISTS \"\${LOCK_BIN}\")
            message(FATAL_ERROR \"lock binary not found at install time: \${LOCK_BIN}\")
        endif()
        file(MAKE_DIRECTORY \"\${DESTDIR}\${CMAKE_INSTALL_PREFIX}/\${CMAKE_INSTALL_DATADIR}/bash-completion/completions\")
        file(MAKE_DIRECTORY \"\${DESTDIR}\${CMAKE_INSTALL_PREFIX}/\${CMAKE_INSTALL_DATADIR}/zsh/site-functions\")
        file(MAKE_DIRECTORY \"\${DESTDIR}\${CMAKE_INSTALL_PREFIX}/\${CMAKE_INSTALL_DATADIR}/fish/vendor_completions.d\")
        execute_process(
            COMMAND \"\${LOCK_BIN}\" --completion bash
            OUTPUT_FILE \"\${DESTDIR}\${CMAKE_INSTALL_PREFIX}/\${CMAKE_INSTALL_DATADIR}/bash-completion/completions/lock\"
            RESULT_VARIABLE _rc_bash)
        execute_process(
            COMMAND \"\${LOCK_BIN}\" --completion zsh
            OUTPUT_FILE \"\${DESTDIR}\${CMAKE_INSTALL_PREFIX}/\${CMAKE_INSTALL_DATADIR}/zsh/site-functions/_lock\"
            RESULT_VARIABLE _rc_zsh)
        execute_process(
            COMMAND \"\${LOCK_BIN}\" --completion fish
            OUTPUT_FILE \"\${DESTDIR}\${CMAKE_INSTALL_PREFIX}/\${CMAKE_INSTALL_DATADIR}/fish/vendor_completions.d/lock.fish\"
            RESULT_VARIABLE _rc_fish)
        foreach(_rc \"_rc_bash\" \"_rc_zsh\" \"_rc_fish\")
            if(NOT \${_rc} EQUAL 0)
                message(FATAL_ERROR \"lock --completion install step failed (rc=\${\${_rc}})\")
            endif()
        endforeach()
        message(STATUS \"lock: installed bash/zsh/fish tab-completion scripts under \${CMAKE_INSTALL_DATADIR}\")
    ")
else()
    message(STATUS "lock: src/main.cpp not found yet -- skipping target 'lock'. "
                   "Add sources to enable the build target.")
endif()

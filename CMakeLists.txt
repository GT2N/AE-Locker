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
    src/crypto.cpp
    src/container.cpp
    src/kdf.cpp
    src/progress.cpp
    src/safe.cpp
    src/term.cpp
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
    )

    target_compile_features(lock PRIVATE cxx_std_20)

    # indicators is a third-party header-only library whose code produces
    # numerous warnings under our strict -Werror -Wconversion -Wsign-conversion
    # flags.  Mark its include directory SYSTEM (-isystem) so that warnings
    # emitted from inside indicators headers are suppressed entirely.
    target_include_directories(lock SYSTEM PRIVATE
        ${indicators_SOURCE_DIR}/include
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

    install(TARGETS lock RUNTIME DESTINATION bin)
else()
    message(STATUS "lock: src/main.cpp not found yet -- skipping target 'lock'. "
                   "Add sources to enable the build target.")
endif()

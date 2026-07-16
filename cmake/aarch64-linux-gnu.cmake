# ─────────────────────────────────────────────────────────────────────────────
# lock: aarch64-linux-gnu 交叉编译 toolchain file
#
# 在 x86_64 主机上使用 clang 的 cross-target 能力为 aarch64 Linux 交叉编译 `lock`，
# 并尽量静态链接（glibc / libstdc++ / libgcc / OpenSSL / readline / tinfo / zlib
# 全部使用 .a），产出可在任意 aarch64 Linux（glibc 版本不低于构建机）上直接
# 运行的 single-binary。
#
# 构建命令:
#     cmake --preset aarch64-static
#     cmake --build --preset aarch64-static
#
# 不影响 default (x86_64) preset —— 本文件仅在显式引用时生效。
# ─────────────────────────────────────────────────────────────────────────────

# CMake 通过三件套识别 cross-compilation target。
set(CMAKE_SYSTEM_NAME      Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# clang 自身的 -target 三元组。CMake 3.15+ 会自动把
# CMAKE_C_COMPILER_TARGET / CMAKE_CXX_COMPILER_TARGET 注入到 -target flag。
set(CMAKE_C_COMPILER_TARGET   aarch64-linux-gnu)
set(CMAKE_CXX_COMPILER_TARGET aarch64-linux-gnu)

# 使用 host 上的 clang + lld 进行 cross-target 编译。
# CMAKE_C_COMPILER 必须是纯 binary 路径，不能带参数；--target 通过
# CMAKE_C_COMPILER_TARGET 自动注入；--sysroot / --gcc-toolchain 通过
# CMAKE_C_FLAGS_INIT 注入。
find_program(_AARCH64_CLANG   clang   REQUIRED)
find_program(_AARCH64_CLANGXX clang++ REQUIRED)

set(CMAKE_C_COMPILER   ${_AARCH64_CLANG})
set(CMAKE_CXX_COMPILER ${_AARCH64_CLANGXX})

# 头文件搜索路径：
#   - libssl-dev:arm64 / libreadline-dev:arm64 把 arch-specific 头 (opensslconf.h)
#     装到 /usr/include/aarch64-linux-gnu/，arch-independent 头 (aes.h 等)
#     复用 /usr/include/openssl/（被 native libssl-dev:amd64 提供）。
#   - clang --target=aarch64-linux-gnu --sysroot=/ 自带搜索 /usr/include 与
#     /usr/include/aarch64-linux-gnu/ 两条 multiarch 路径。
# 库搜索路径：
#   - libstdc++.a / libgcc.a 在 /usr/lib/gcc/aarch64-linux-gnu/14/，需要
#     --gcc-toolchain=/usr 让 clang 把该路径加到 link search path。
set(CMAKE_C_FLAGS_INIT
    "--target=aarch64-linux-gnu --sysroot=/ --gcc-toolchain=/usr")
set(CMAKE_CXX_FLAGS_INIT
    "--target=aarch64-linux-gnu --sysroot=/ --gcc-toolchain=/usr")

# GNU-binutils 的交叉工具：archiver / indexer / 字符串与符号查阅。
# LLD 本身支持 aarch64，但 ar/ranlib/readelf 仍然按 arch 区分格式。
find_program(_AARCH64_AR      aarch64-linux-gnu-ar      REQUIRED)
find_program(_AARCH64_RANLIB  aarch64-linux-gnu-ranlib  REQUIRED)
find_program(_AARCH64_OBJDUMP aarch64-linux-gnu-objdump REQUIRED)
find_program(_AARCH64_READELF aarch64-linux-gnu-readelf REQUIRED)
find_program(_AARCH64_STRIP   aarch64-linux-gnu-strip   REQUIRED)

set(CMAKE_AR      ${_AARCH64_AR})
set(CMAKE_RANLIB  ${_AARCH64_RANLIB})
set(CMAKE_OBJDUMP ${_AARCH64_OBJDUMP})
set(CMAKE_READELF ${_AARCH64_READELF})
set(CMAKE_STRIP   ${_AARCH64_STRIP})

# 让 find_package / find_library 优先匹配 multiarch arm64 目录。
# CMake 会自动把 CMAKE_LIBRARY_ARCHITECTURE 拼到 /usr/lib/<arch>/ 的搜索路径前。
set(CMAKE_LIBRARY_ARCHITECTURE aarch64-linux-gnu)

# 关键: find_library 优先选静态库 (.a)，让 OpenSSL::Crypto / readline / tinfo /
# zlib 等通过 find_library 拿到静态版本，便于最终 `-static` 完全静态化。
# 必须用 CACHE ... FORCE：toolchain file 在 project() 之前被读，此时 CMake
# 还没初始化 CMAKE_FIND_LIBRARY_SUFFIXES 的默认 cache 值 (".so;.a" on Linux)。
# 普通 set(...) 是 normal var，会被后续 enable_language() 时 CMake 内部的
# cache 初始化覆盖；CACHE ... FORCE 才能真正持久化到 cache，使所有 find_library
# 都只匹配 .a。
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" CACHE STRING "" FORCE)

# 链接器:
#   -static              让所有运行时库转为 .a，无 NEEDED 项
#   -fuse-ld=lld         使用 host 的 lld（LLD 自身就是 cross-target linker）
#   --ld-path=/usr/bin/ld.lld   显式锁定 LLD 路径（与 CMakeLists 的 LLD 检查一致）
#   -L<link-dirs>        zstd 的 libzstd_static target 暴露 INTERFACE_LINK_LIBRARIES
#     含 `-lzstd`（zstd 自身的 CMakeLists 把 zstd 作为外部依赖兜底）。
#     build-aarch64/_deps/zstd-build/lib/libzstd.a 是 FetchContent 已经 built 的
#     arm64 静态副本，但 link line 中 `-lzstd` 找不到它，因为它不在 default
#     search path。我们提前用 -L 显式 append build-aarch64 的 zstd build lib
#     目录到 link search path，让 `-lzstd` resolve 到 FetchContent 的 .a 而非
#     报 "unable to find library -lzstd"。default preset 不受影响（没引 toolchain）。
set(_AARCH64_BUILD_DIR "${CMAKE_SOURCE_DIR}/build-aarch64")
set(CMAKE_EXE_LINKER_FLAGS_INIT
    "-static -fuse-ld=lld --ld-path=/usr/bin/ld.lld --gcc-toolchain=/usr --target=aarch64-linux-gnu --sysroot=/ -L${_AARCH64_BUILD_DIR}/_deps/zstd-build/lib -L${_AARCH64_BUILD_DIR}/_deps/lz4-build -L${_AARCH64_BUILD_DIR}/_deps/ftxui-build")

# 强制让 find_package(OpenSSL) 直接命中 arm64 静态版。FindOpenSSL 模块在
# 没有 multiarch hint 时会优先找到 $host_arch/libcrypto.so。我们用
# CACHE ... FORCE 直接覆盖 FindOpenSSL 模块写入 cache 的 4 个 result var，
# 使其在 incremental cmake -B build-aarch64 时 cache 不会 drift 回 x86_64 版本。
# Debian multiarch layout:
#   include:   /usr/include/openssl/*.h     (arch-independent, cross-compile OK)
#              /usr/include/aarch64-linux-gnu/openssl/opensslconf.h (arch-specific)
#              clang --target=... 会两条路径都搜
#   lib:       /usr/lib/aarch64-linux-gnu/libcrypto.a  / libssl.a
set(OPENSSL_USE_STATIC_LIBS ON CACHE BOOL "Prefer static OpenSSL libs (.a)" FORCE)
set(OPENSSL_INCLUDE_DIR    "/usr/include" CACHE PATH "OpenSSL headers (arch-indep)" FORCE)
set(OPENSSL_CRYPTO_LIBRARY "/usr/lib/aarch64-linux-gnu/libcrypto.a" CACHE FILEPATH
    "OpenSSL arm64 static libcrypto" FORCE)
set(OPENSSL_SSL_LIBRARY     "/usr/lib/aarch64-linux-gnu/libssl.a"     CACHE FILEPATH
    "OpenSSL arm64 static libssl"    FORCE)
set(OPENSSL_VERSION         "3.5.6" CACHE STRING "OpenSSL version hint" FORCE)
unset(OPENSSL_ROOT_DIR CACHE)

# Readline 同 OpenSSL 的问题：CMakeLists.txt 用 find_library 找 readline + tinfo，
# 结果会被 cache；首次配置若找到 .so 就持久化。CMAKE_FIND_LIBRARY_SUFFIXES=.a
# 对于已 cache 的 Readline_LIBRARY 不会重 search。直接 force cache 到 absolute
# .a 路径，与 OpenSSL pattern 一致。
set(Readline_LIBRARY       "/usr/lib/aarch64-linux-gnu/libreadline.a"
    CACHE FILEPATH "GNU readline static lib (arm64)" FORCE)
set(Readline_INCLUDE_DIR   "/usr/include"
    CACHE PATH     "readline headers (arch-indep)" FORCE)
set(Readline_TINFO_LIBRARY "/usr/lib/aarch64-linux-gnu/libtinfo.a"
    CACHE FILEPATH "libtinfo static lib (arm64)" FORCE)



# Threads::Threads 在 cross 下若不走 pthread-config probe 而走 -lpthread，
# 仍要落入静态。CMAKE_FIND_LIBRARY_SUFFIXES=.a 已覆盖。

# ─────────────────────────────────────────────────────────────────────────────
# 关键：让 CMake 的 try_compile / try_link 不去 link 成 ELF，而是组装成
# STATIC_LIBRARY。cross-toolchain + -static 时 link 一个独立的 .c 探针会
# 失败（pthread.h 必须从 libc.a 链入，但 try_compile 输入的 .c 不是 lock 本身的
# sources，多半链不到真实所有符号）。把探针改成 STATIC_LIBRARY 后不执行 link，
# 只验证 compiler + 汇编 OK，彻底绕开 cross-static try-link 死锁。这个开关
# 不影响 lock 本身的最终 link —— lock 的 add_executable 仍然会完整链接。
# ─────────────────────────────────────────────────────────────────────────────
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

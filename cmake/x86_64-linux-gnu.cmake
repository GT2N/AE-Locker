# ─────────────────────────────────────────────────────────────────────────────
# ae-locker: x86_64-linux-gnu native static toolchain file
#
# 在 x86_64 主机上使用 host clang 全静态编译 `ae-locker`,产出无 NEEDED 项的
# single static-pie binary,可跨 glibc 同代版本在任意 x86_64 Linux 上直接跑.
#
# 构建命令:
#     cmake --preset x86_64-static
#     cmake --build --preset x86_64-static
#
# 不影响 default preset —— 本文件仅在显式引用时生效.
# ─────────────────────────────────────────────────────────────────────────────

# CMake 通过三件套识别 native target;这里 target = 主机的 x86_64.
set(CMAKE_SYSTEM_NAME      Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# 使用 host 上的 clang + lld.
find_program(_X86_64_CLANG   clang   REQUIRED)
find_program(_X86_64_CLANGXX clang++ REQUIRED)

set(CMAKE_C_COMPILER   ${_X86_64_CLANG})
set(CMAKE_CXX_COMPILER ${_X86_64_CLANGXX})

# 不设 CMAKE_C_COMPILER_TARGET / CMAKE_CXX_COMPILER_TARGET —— 用 clang 默认
# target 即可 (host triple 即 x86_64-linux-gnu).无需 --target / --sysroot /
# --gcc-toolchain flag.

# ARCHIVER / LINKER 一律用 host-native 工具.binutils 不需要分 arch 因为
# 我们用 host 默认的 /usr/bin/ar 即 native x86_64 工具.
set(CMAKE_AR      /usr/bin/ar)
set(CMAKE_RANLIB  /usr/bin/ranlib)
set(CMAKE_OBJDUMP /usr/bin/objdump)
set(CMAKE_READELF /usr/bin/readelf)
set(CMAKE_STRIP   /usr/bin/strip)

# 让 find_package / find_library 优先匹配 multiarch x86_64 静态库路径.
set(CMAKE_LIBRARY_ARCHITECTURE x86_64-linux-gnu)

# 关键: find_library 优先选静态库 (.a),让 OpenSSL::Crypto / readline / tinfo /
# zlib 通过 find_library 拿到静态版本,便于最终 `-static-pie` 完全静态化.
# 必须用 CACHE ... FORCE:toolchain file 在 project() 之前被读,此时 CMake 还
# 没初始化 CMAKE_FIND_LIBRARY_SUFFIXES 的默认 cache 值 (".so;.a" on Linux).
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" CACHE STRING "" FORCE)

# 链接器:
#   -static-pie         让所有运行时库转为 .a,无 NEEDED 项;同时生成
#                       Position-Independent Executable(ET_DYN 类型),兼容
#                       现代 Linux 发行版默认强制的 PIE.
#   -fuse-ld=lld        使用 host 的 lld
#   --ld-path=/usr/bin/ld.lld  显式锁定 LLD 路径(与 CMakeLists 的 LLD 检查一致)
#   -L<build-dirs>      FetchContent 已 built 的 zstd / lz4 / ftxui 静态库
#     落在 build-static/_deps/{zstd,lz4,ftxui}-build/lib 下.zstd 的
#     libzstd_static target 暴露 INTERFACE_LINK_LIBRARIES 含 `-lzstd`,但
#     `-lzstd` 找不到 FetchContent 的副本因为它不在 default search path.
#     提前 -L 显式 append build-static 的 _deps build lib 目录到 link search
#     path,让 `-lzstd` resolve 到 FetchContent 的 .a 而非系统 .so.
set(_X86_64_BUILD_DIR "${CMAKE_SOURCE_DIR}/build-x86_64-static")
set(CMAKE_EXE_LINKER_FLAGS_INIT
    "-static-pie -fuse-ld=lld --ld-path=/usr/bin/ld.lld -L${_X86_64_BUILD_DIR}/_deps/zstd-build/lib -L${_X86_64_BUILD_DIR}/_deps/lz4-build -L${_X86_64_BUILD_DIR}/_deps/ftxui-build")

# 强制让 find_package(OpenSSL) 直接命中 x86_64 静态版.与 aarch64 toolchain 一
# 致,用 CACHE ... FORCE 直接覆盖 FindOpenSSL 的 cache var,使 incremental
# cmake -B build-x86_64-static 时 cache 不会 drift 回 .so 版本.
set(OPENSSL_USE_STATIC_LIBS ON CACHE BOOL "Prefer static OpenSSL libs (.a)" FORCE)
set(OPENSSL_INCLUDE_DIR    "/usr/include" CACHE PATH "OpenSSL headers" FORCE)
set(OPENSSL_CRYPTO_LIBRARY "/usr/lib/x86_64-linux-gnu/libcrypto.a" CACHE FILEPATH
    "OpenSSL x86_64 static libcrypto" FORCE)
set(OPENSSL_SSL_LIBRARY     "/usr/lib/x86_64-linux-gnu/libssl.a"     CACHE FILEPATH
    "OpenSSL x86_64 static libssl"    FORCE)
unset(OPENSSL_ROOT_DIR CACHE)

# Readline:CMakeLists.txt 用 find_library 找 readline + tinfo,会被 cache;
# 首次配置若找到 .so 就持久化.直接 force cache 到 absolute .a 路径,与
# OpenSSL pattern 一致.
set(Readline_LIBRARY       "/usr/lib/x86_64-linux-gnu/libreadline.a"
    CACHE FILEPATH "GNU readline static lib (x86_64)" FORCE)
set(Readline_INCLUDE_DIR   "/usr/include"
    CACHE PATH     "readline headers" FORCE)
set(Readline_TINFO_LIBRARY "/usr/lib/x86_64-linux-gnu/libtinfo.a"
    CACHE FILEPATH "libtinfo static lib (x86_64)" FORCE)

# libstdc++ / libgcc 静态库在 /usr/lib/gcc/x86_64-linux-gnu/14/,LLD 默认会
# 去 --gcc-toolchain 路径找它们.在 native build 下 clang 的 builtin search
# 路径已包含 /usr/lib/gcc/x86_64-linux-gnu/14/,无需 --gcc-toolchain 注入.

# Threads::Threads 在 CMAKE_FIND_LIBRARY_SUFFIXES=.a 下会落到 libpthread.a,
# 从而被静态 link.-static-pie 也确保 libc / libdl / libm / librt 全部用 .a.

# 让 CMake 的 try_compile / try_link 不去 link 成 ELF, 同 aarch64 toolchain:
# 避免静态 link 探针失败 (静态 link 一个独立 .c 探针需要把所有符号完整 link
# 进去,容易失败).STATIC_LIBRARY 类型只验证 compiler + 汇编 OK.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

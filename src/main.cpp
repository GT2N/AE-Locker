#include <ae-locker/cli.hpp>
#include <ae-locker/errors.hpp>

#include <exception>
#include <iostream>

// ─────────────────────────────────────────────────────────────────────────────
// Android Bionic TLS 对齐兼容性 hack
//
// Android Bionic linker (linker64) 对 ET_DYN/PIE 可执行文件有硬性约束:
//   PT_TLS 段的 p_align 必须 >= 64 字节 (AArch64 / Bionic arm64)。
//   若 binary 是 static-pie 且 PT_TLS 对齐 < 64, 会立即 abort 并打印:
//     "executable's TLS segment is underaligned: alignment is 8, needs to be
//      at least 64 for ARM64 Bionic"
//
// 我们在 x86_64 主机上用 Debian multiarch 的 arm64 glibc 静态库交叉编译
// `ae-locker` 时, glibc 静态库里的 thread_local 变量默认 alignment 是 8 字节,
// 导致 LLD 把 PT_TLS 段的 alignment 合并为 8。LLD 19 没有提供
// `--tls-align` 之类的开关直接强制抬高对齐, 所以我们从源码侧注入
// 一个 alignas(64) thread_local 哑变量: 只要把这一个 TLS symbol 的对齐
// 提到 64 字节, LLD 在 merge 时就会把整个 PT_TLS 段的 p_align 也抬到 64,
// 因此对 glibc 内部 thread_local 变量的 alignment 无需改动。
//
// 这个变量在整个程序执行期间从不被读写, 也不被 ELF 符号表导出 (匿名
// namespace 内的 internal linkage), 只占 64 字节的 TLS slot。开销极小,
// 且只在 binary 拥有 TLS 段时才生效 (本程序永远有 TLS 段, 因为 libc /
// libstdc++ / libpthread / SafeIstream 都依赖 thread_local)。
//
// 同样的 fix 也对 musl/arm64 静态 binary 的 Android 兼容性有益 (musl
// 不要求 64 对齐但 Bionic 仍要求); 对 Linux glibc host 运行完全无副作用。
// ─────────────────────────────────────────────────────────────────────────────
namespace {
// `[[gnu::used]]` 让编译器不会因 -O3 -flto=thin 把这个 unused symbol 优化掉
// (实测只用 [[maybe_unused]] 会被 LTO 整个 elide 掉, BuildID 都不变, TLS
//  段 alignment 仍是 8)。`[[gnu::retain]]` 让链接器 (LLD --gc-sections 时)
// 也保留这个 section。两者一起才能扛过 LTO + --gc-sections。
[[gnu::used, gnu::retain]] alignas(64) thread_local
char tls_align_pad_64_[64] = {};
}

int main(int argc, char** argv) {
    try {
        return ae_locker::cli_main(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "ae-locker: uncaught exception: " << e.what() << "\n";
        return static_cast<int>(ae_locker::ExitCode::Internal);
    } catch (...) {
        std::cerr << "ae-locker: unknown exception\n";
        return static_cast<int>(ae_locker::ExitCode::Internal);
    }
}

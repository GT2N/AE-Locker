#include <lock/cli.hpp>
#include <lock/errors.hpp>

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
    try {
        return lock::cli_main(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "lock: uncaught exception: " << e.what() << "\n";
        return static_cast<int>(lock::ExitCode::Internal);
    } catch (...) {
        std::cerr << "lock: unknown exception\n";
        return static_cast<int>(lock::ExitCode::Internal);
    }
}

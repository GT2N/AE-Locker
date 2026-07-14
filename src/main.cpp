#include <lock/cli.hpp>

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
    try {
        return lock::cli_main(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "lock: uncaught exception: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "lock: unknown exception\n";
        return 1;
    }
}

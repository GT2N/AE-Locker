// lock::cli — argv parsing, subcommand dispatch, and file-orchestration glue
// between the password acquirer, the KDF, the crypto core, and the progress
// tracker. main() (in main.cpp) delegates everything to cli_main().
#include <lock/cli.hpp>

#include <lock/constants.hpp>
#include <lock/container.hpp>
#include <lock/crypto.hpp>
#include <lock/kdf.hpp>
#include <lock/progress.hpp>
#include <lock/safe.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace lock {

namespace {

struct ParsedArgs {
    std::vector<std::string> files;
    std::string password_file;
    bool password_env_var = false;
    bool no_safe          = false;
    uint32_t jobs         = 0;
    std::string output_dir;
    uint32_t chunk_size   = (uint32_t)DEFAULT_CHUNK_SIZE;
    bool verbose          = false;
    bool quiet            = false;
    std::string error;
};

bool split_eq(std::string_view token,
              std::string& name_out,
              std::string& value_out) {
    if (token.size() < 3 || token[0] != '-' || token[1] != '-') {
        return false;
    }
    auto eq = token.find('=');
    if (eq == std::string_view::npos) {
        return false;
    }
    name_out  = std::string(token.substr(0, eq));
    value_out = std::string(token.substr(eq + 1));
    return true;
}

bool parse_uint32(const std::string& flag_name,
                  const std::string& v,
                  uint32_t min_v,
                  uint32_t max_v,
                  uint32_t& out,
                  ParsedArgs& pa) {
    if (v.empty() || v[0] == '-') {
        pa.error = "flag " + flag_name + " requires a non-negative integer";
        return false;
    }
    try {
        unsigned long long parsed = std::stoull(v);
        if (parsed < min_v || parsed > max_v) {
            pa.error = "flag " + flag_name + " value out of range [" +
                       std::to_string(min_v) + ", " + std::to_string(max_v) + "]";
            return false;
        }
        out = static_cast<uint32_t>(parsed);
        return true;
    } catch (const std::exception&) {
        pa.error = "flag " + flag_name + " requires an integer value";
        return false;
    }
}

bool apply_flag_value(ParsedArgs& pa,
                      const std::string& flag,
                      const std::string& value) {
    if (flag == "-p" || flag == "--password-file") {
        pa.password_file = value;
        return true;
    }
    if (flag == "-o" || flag == "--output-dir") {
        pa.output_dir = value;
        return true;
    }
    if (flag == "-j" || flag == "--jobs") {
        return parse_uint32(flag, value, 1u, 1024u, pa.jobs, pa);
    }
    if (flag == "--chunk-size") {
        return parse_uint32(flag, value, 4096u,
                            static_cast<uint32_t>(1024u * 1024u * 16u),
                            pa.chunk_size, pa);
    }
    pa.error = "internal: unknown flag '" + flag + "'";
    return false;
}

ParsedArgs parse_args(const std::vector<std::string>& args, size_t offset) {
    ParsedArgs pa;

    for (size_t i = offset; i < args.size(); ++i) {
        const std::string& tok = args[i];

        if (tok == "-h" || tok == "--help") {
            continue;
        }
        if (tok == "-q" || tok == "--quiet") {
            pa.quiet = true;
            continue;
        }
        if (tok == "-v" || tok == "--verbose") {
            pa.verbose = true;
            continue;
        }
        if (tok == "--no-safe") {
            pa.no_safe = true;
            continue;
        }
        if (tok == "-pev" || tok == "--password-env-var") {
            pa.password_env_var = true;
            continue;
        }

        if (tok == "-p" || tok == "--password-file" ||
            tok == "-j" || tok == "--jobs" ||
            tok == "-o" || tok == "--output-dir" ||
            tok == "--chunk-size") {
            if (i + 1 >= args.size()) {
                pa.error = "flag " + tok + " requires a value";
                break;
            }
            if (!apply_flag_value(pa, tok, args[i + 1])) {
                break;
            }
            ++i;
            continue;
        }

        std::string flag_name, value;
        if (split_eq(tok, flag_name, value)) {
            if (flag_name == "-p" || flag_name == "--password-file" ||
                flag_name == "-j" || flag_name == "--jobs" ||
                flag_name == "-o" || flag_name == "--output-dir" ||
                flag_name == "--chunk-size") {
                if (!apply_flag_value(pa, flag_name, value)) {
                    break;
                }
                continue;
            }
        }

        if (tok.empty()) {
            continue;
        }
        if (tok[0] == '-') {
            pa.error = "unknown flag '" + tok + "'";
            break;
        }
        pa.files.push_back(tok);
    }

    return pa;
}

void print_usage() {
    std::cout <<
        "lock 1.0.0 — AES-256-CTR + HMAC-SHA256 file encryption\n"
        "\n"
        "Usage:\n"
        "  lock <command> [options] <file> [<file> ...]\n"
        "  lock -c <command> [options] <file> [<file> ...]\n"
        "  lock --cli\n"
        "  lock --help | --version\n"
        "\n"
        "Commands:\n"
        "  encrypt    Encrypt one or more files into .locked containers\n"
        "  decrypt    Decrypt one or more .locked containers\n"
        "  list       Print the metadata of a .locked container without decrypting\n"
        "\n"
        "Options:\n"
        "  -p, --password-file <path>  Read password from <path> (requires --no-safe)\n"
        "      --password-env-var       Read password from $LOCK_PASSWORD (requires --no-safe)\n"
        "      --no-safe                Acknowledge unsafe password sources\n"
        "  -j, --jobs <N>               Per-file worker threads (default: hardware_concurrency)\n"
        "  -o, --output-dir <dir>      Output directory (default: same dir as input file)\n"
        "      --chunk-size <bytes>     Encryption chunk size (default 1 MiB; >=4096 and /16)\n"
        "  -v, --verbose                Print extra status to stderr\n"
        "  -q, --quiet                  Suppress progress bars (errors still shown)\n"
        "      --version                Print version and exit\n"
        "  -h, --help                   Print this help and exit\n";
}

std::string to_hex(const unsigned char* p, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(digits[(p[i] >> 4) & 0x0F]);
        out.push_back(digits[p[i] & 0x0F]);
    }
    return out;
}

uint32_t default_jobs() {
    auto hc = std::thread::hardware_concurrency();
    return (hc == 0) ? 1u : static_cast<uint32_t>(hc);
}

// ---------------------------------------------------------------------------
// Encrypt orchestration: 1 password acquisition, shared salt/iv/key-material,
// one std::thread per input file (inter-file parallelism), each of which calls
// encrypt_file with its intra-file thread count (EncryptOptions::num_threads).
// ---------------------------------------------------------------------------
struct EncryptCliArgs {
    std::vector<std::string> files;
    PasswordMode password_mode = PasswordMode::Interactive;
    std::string password_file;
    bool no_safe          = false;
    uint32_t jobs         = 0;
    std::string output_dir;
    uint32_t chunk_size   = (uint32_t)DEFAULT_CHUNK_SIZE;
    bool verbose          = false;
    bool quiet            = false;
};

int run_encrypt(const EncryptCliArgs& args, ProgressTracker& tracker) {
    PasswordRequest req;
    req.mode     = args.password_mode;
    req.file_path = args.password_file;
    req.no_safe  = args.no_safe;
    PasswordResult pw = acquire_password(req);
    if (!pw.warn.empty() && args.verbose) {
        std::cerr << "warning: " << pw.warn << "\n";
    }

    // One salt/iv for the whole invocation; each file's header stores
    // (and re-encrypts against) the same value.
    auto salt = generate_salt();
    auto iv  = random_bytes(IV_SIZE);
    if (iv.size() < IV_SIZE) {
        throw std::runtime_error("random_bytes(Iv) returned short buffer");
    }
    std::array<unsigned char, IV_SIZE> base_iv{};
    std::copy_n(iv.begin(), IV_SIZE, base_iv.begin());

    ScryptParams sp{};
    auto km = derive_key_scrypt(pw.password, salt, sp);

    // Refuse to overwrite existing output BEFORE spawning any worker — the
    // existence check must run on the main thread so no race is possible.
    std::vector<std::filesystem::path> output_paths;
    output_paths.reserve(args.files.size());
    for (const auto& input : args.files) {
        std::filesystem::path output_path =
            args.output_dir.empty()
                ? std::filesystem::path(input).concat(LOCKED_EXTENSION)
                : std::filesystem::path(args.output_dir) /
                      (std::filesystem::path(input).filename().string() +
                       LOCKED_EXTENSION);
        if (std::error_code ec; std::filesystem::exists(output_path, ec)) {
            std::cerr << "error: '" << output_path.string()
                      << "' already exists. Remove it or choose a different "
                         "output directory.\n";
            return 1;
        }
        output_paths.push_back(std::move(output_path));
    }

    if (!args.output_dir.empty()) {
        if (std::error_code ec; !std::filesystem::is_directory(args.output_dir, ec)) {
            std::cerr << "error: output directory '" << args.output_dir
                      << "' does not exist\n";
            return 1;
        }
    }

    if (!args.quiet) {
        tracker.start(args.files.size());
    }

    std::vector<std::thread> workers;
    workers.reserve(args.files.size());
    std::atomic<size_t> files_done{0};
    std::mutex error_mutex;
    std::optional<std::string> first_error;

    for (size_t i = 0; i < args.files.size(); ++i) {
        const std::string& input    = args.files[i];
        const std::filesystem::path& output_path = output_paths[i];

        uintmax_t file_size = std::filesystem::file_size(input);
        uintmax_t cs = static_cast<uintmax_t>(args.chunk_size);
        uintmax_t chunks = (file_size + cs - 1) / cs;
        size_t total_chunks = static_cast<size_t>(chunks);

        if (!args.quiet) {
            tracker.start_file(i, std::filesystem::path(input).filename().string(),
                               total_chunks);
        }

        uint32_t num_threads = (args.jobs == 0) ? default_jobs() : args.jobs;

        workers.emplace_back(
            [&, i, input, output_path,
             file_key    = km.file_key,
             hmac_key    = km.hmac_key,
             salt, base_iv, num_threads]() {
                EncryptOptions opts;
                opts.file_key    = file_key;
                opts.hmac_key    = hmac_key;
                opts.salt        = salt;
                opts.base_iv     = base_iv;
                opts.kdf_N       = static_cast<uint32_t>(SCRYPT_DEFAULT_N);
                opts.kdf_r       = SCRYPT_DEFAULT_R;
                opts.kdf_p       = SCRYPT_DEFAULT_P;
                opts.chunk_size  = args.chunk_size;
                opts.num_threads = num_threads;
                opts.progress    = args.quiet
                                       ? ProgressCallback{}
                                       : tracker.make_callback(i, args.chunk_size);
                try {
                    encrypt_file(input, output_path.string(),
                                 std::filesystem::path(input).filename().string(),
                                 opts);
                    if (!args.quiet) {
                        tracker.finish_file(i);
                    }
                    files_done.fetch_add(1, std::memory_order_relaxed);
                } catch (const std::exception& e) {
                    std::lock_guard<std::mutex> lock(error_mutex);
                    if (!first_error) {
                        first_error = input + ": " + e.what();
                    }
                }
            });
    }

    for (auto& t : workers) {
        t.join();
    }

    if (!args.quiet) {
        tracker.finish();
    }

    if (first_error) {
        std::cerr << "error: " << *first_error << "\n";
        return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Decrypt orchestration: password acquisition, per-file thread that re-derives
// keys from the salt+scrypt params stored in the file header, restores the
// encrypted-or-fallback filename, then calls decrypt_file.
// ---------------------------------------------------------------------------
struct DecryptCliArgs {
    std::vector<std::string> files;
    PasswordMode password_mode = PasswordMode::Interactive;
    std::string password_file;
    bool no_safe          = false;
    uint32_t jobs         = 0;
    std::string output_dir;
    bool verbose          = false;
    bool quiet            = false;
};

int run_decrypt(const DecryptCliArgs& args, ProgressTracker& tracker) {
    PasswordRequest req;
    req.mode     = args.password_mode;
    req.file_path = args.password_file;
    req.no_safe  = args.no_safe;
    PasswordResult pw = acquire_password(req);
    if (!pw.warn.empty() && args.verbose) {
        std::cerr << "warning: " << pw.warn << "\n";
    }

    if (!args.output_dir.empty()) {
        if (std::error_code ec; !std::filesystem::is_directory(args.output_dir, ec)) {
            std::cerr << "error: output directory '" << args.output_dir
                      << "' does not exist\n";
            return 1;
        }
    }

    for (const auto& input : args.files) {
        if (!HeaderReader::is_locked_file(input)) {
            std::cerr << "error: '" << input
                      << "' is not a .locked file (bad magic)\n";
            return 1;
        }
    }

    if (!args.quiet) {
        tracker.start(args.files.size());
    }

    std::vector<std::thread> workers;
    workers.reserve(args.files.size());
    std::atomic<size_t> files_done{0};
    std::mutex error_mutex;
    std::optional<std::string> first_error;

    for (size_t i = 0; i < args.files.size(); ++i) {
        const std::string& input = args.files[i];

        workers.emplace_back(
            [&, i, input, password = pw.password]() {
                try {
                    std::ifstream in(input, std::ios::binary);
                    in.exceptions(std::ios::goodbit);
                    FileHeader header = HeaderReader::read(in);
                    in.close();

                    ScryptParams sp;
                    sp.N = static_cast<uint64_t>(header.kdf_N);
                    sp.r = header.kdf_r;
                    sp.p = header.kdf_p;
                    auto km = derive_key_scrypt(password, header.salt, sp);

                    std::string original_name;
                    if ((header.flags & 0x01u) != 0u) {
                        std::string_view enc_sv(
                            reinterpret_cast<const char*>(
                                header.encrypted_filename.data()),
                            header.encrypted_filename.size());
                        original_name = decrypt_filename(
                            km.file_key, header, enc_sv,
                            std::span<const unsigned char, FILENAME_TAG_SIZE>(
                                header.filename_tag.data(), FILENAME_TAG_SIZE));
                    } else {
                        // Fall back: strip ".locked" from the input filename.
                        // kExtLen is 7 ("strlen of ".locked'").
                        std::string fn =
                            std::filesystem::path(input).filename().string();
                        constexpr size_t kExtLen = 7;
                        if (fn.size() >= kExtLen &&
                            fn.compare(fn.size() - kExtLen, kExtLen,
                                        LOCKED_EXTENSION) == 0) {
                            original_name = fn.substr(0, fn.size() - kExtLen);
                        } else {
                            original_name = "decrypted.dat";
                        }
                    }

                    // The restored filename could carry ../ segments packed in
                    // by an attacker — take only the leaf to prevent path
                    // traversal outside output_dir.
                    std::filesystem::path safe_name =
                        std::filesystem::path(original_name).filename();
                    if (safe_name.empty()) {
                        safe_name = "decrypted.dat";
                    }

                    std::filesystem::path output_path =
                        args.output_dir.empty()
                            ? std::filesystem::path(input).parent_path() /
                                  safe_name
                            : std::filesystem::path(args.output_dir) / safe_name;

                    if (std::error_code ec;
                        std::filesystem::exists(output_path, ec)) {
                        throw std::runtime_error(
                            "'" + output_path.string() + "' already exists");
                    }

                    uintmax_t cs = static_cast<uintmax_t>(header.chunk_size);
                    uintmax_t chunks =
                        (header.original_size + cs - 1) / cs;
                    size_t total_chunks = static_cast<size_t>(chunks);

                    if (!args.quiet) {
                        tracker.start_file(i, safe_name.string(),
                                          total_chunks);
                    }

                    uint32_t num_threads =
                        (args.jobs == 0) ? default_jobs() : args.jobs;

                    DecryptOptions opts;
                    opts.file_key    = km.file_key;
                    opts.hmac_key    = km.hmac_key;
                    opts.num_threads = num_threads;
                    opts.progress    = args.quiet
                                           ? ProgressCallback{}
                                           : tracker.make_callback(i,
                                               static_cast<size_t>(
                                                   header.chunk_size));

                    decrypt_file(input, output_path.string(), opts);

                    if (!args.quiet) {
                        tracker.finish_file(i);
                    }
                    files_done.fetch_add(1, std::memory_order_relaxed);
                } catch (const std::exception& e) {
                    std::lock_guard<std::mutex> lock(error_mutex);
                    if (!first_error) {
                        first_error = input + ": " + e.what();
                    }
                }
            });
    }

    for (auto& t : workers) {
        t.join();
    }

    if (!args.quiet) {
        tracker.finish();
    }

    if (first_error) {
        std::cerr << "error: " << *first_error << "\n";
        return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// List: dump the file header metadata without touching the password or data.
// ---------------------------------------------------------------------------
int run_list(const std::vector<std::string>& files) {
    for (const auto& input : files) {
        std::cout << "File: " << input << "\n";
        if (!HeaderReader::is_locked_file(input)) {
            std::cout << "  (not a .locked file)\n\n";
            continue;
        }
        try {
            std::ifstream in(input, std::ios::binary);
            FileHeader h = HeaderReader::read(in);

            std::cout << "  magic:         ENCF0001v1\n";
            std::cout << "  version:       " << h.version << "\n";
            std::cout << "  algorithm:     AES-256-CTR + HMAC-SHA256 (0x"
                      << std::hex << h.algorithm_id << std::dec << ")\n";
            std::cout << "  KDF:           scrypt (N=" << h.kdf_N
                      << " r=" << h.kdf_r << " p=" << h.kdf_p << ")\n";
            std::cout << "  salt:          "
                      << to_hex(h.salt.data(), h.salt.size()) << "\n";
            std::cout << "  base_iv:       "
                      << to_hex(h.base_iv.data(), h.base_iv.size()) << "\n";
            std::cout << "  original_size: " << h.original_size << " bytes\n";
            std::cout << "  chunk_size:    " << h.chunk_size << " bytes\n";
            std::cout << "  chunk_count:   " << h.chunk_count << "\n";
            std::cout << "  filename_len:  " << h.filename_len << "\n";
            std::cout << "  data_offset:   " << h.data_offset() << " bytes\n";
            std::uintmax_t total_size = std::filesystem::file_size(input);
            std::cout << "  file_size:     " << total_size << " bytes\n";
            std::uintmax_t overhead = (h.original_size >= total_size)
                                          ? 0
                                          : (total_size - h.original_size);
            double denom = (total_size == 0) ? 1.0
                                             : static_cast<double>(total_size);
            std::cout << "  overhead:      " << overhead << " bytes ("
                      << std::fixed << std::setprecision(3)
                      << (100.0 * static_cast<double>(overhead) / denom)
                      << "%)\n";
        } catch (const std::exception& e) {
            std::cout << "  error: " << e.what() << "\n";
        }
        std::cout << "\n";
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Interactive (--cli): minimal loop that prompts for a subcommand + file
// paths, acquires the password interactively (always PasswordMode::Interactive
// — interactive mode never accepts -p / -pev), and dispatches to the same
// run_encrypt / run_decrypt / run_list entry points as subcommand mode.
// ---------------------------------------------------------------------------
int run_interactive(std::vector<std::string> /*rest*/) {
    std::cerr << "lock interactive mode\n";
    std::cerr << "Commands: encrypt, decrypt, list, quit\n";

    std::string line;
    while (std::cerr << "> " && std::getline(std::cin, line)) {
        size_t first_nonspace = line.find_first_not_of(" \t");
        if (first_nonspace == std::string::npos) {
            continue;
        }
        line = line.substr(first_nonspace);

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        if (cmd == "quit" || cmd == "exit" || cmd == "q") {
            return 0;
        }
        if (cmd != "encrypt" && cmd != "decrypt" && cmd != "list") {
            std::cerr << "  unknown command '" << cmd
                      << "' — try 'encrypt', 'decrypt', 'list', or 'quit'\n";
            continue;
        }

        std::vector<std::string> files;
        std::string tok;
        while (iss >> tok) {
            files.push_back(tok);
        }
        while (true) {
            std::cerr << "  file path (empty line to finish): ";
            std::string p;
            if (!std::getline(std::cin, p)) {
                return 0;
            }
            size_t ns = p.find_first_not_of(" \t");
            if (ns == std::string::npos) {
                break;
            }
            p = p.substr(ns);
            size_t last = p.find_last_not_of(" \t");
            if (last != std::string::npos) {
                p.erase(last + 1);
            }
            files.push_back(p);
        }
        if (files.empty()) {
            std::cerr << "  no files specified — aborted\n";
            continue;
        }

        if (cmd == "list") {
            run_list(files);
            continue;
        }

        ProgressTracker etracker;
        if (cmd == "encrypt") {
            EncryptCliArgs eargs;
            eargs.files         = files;
            eargs.password_mode = PasswordMode::Interactive;
            eargs.chunk_size    = (uint32_t)DEFAULT_CHUNK_SIZE;
            eargs.jobs          = 0;
            eargs.quiet         = true;
            (void)run_encrypt(eargs, etracker);
        } else {
            DecryptCliArgs dargs;
            dargs.files         = files;
            dargs.password_mode = PasswordMode::Interactive;
            dargs.jobs          = 0;
            dargs.quiet         = true;
            (void)run_decrypt(dargs, etracker);
        }
    }
    return 0;
}

}  // namespace

// ---------------------------------------------------------------------------
// cli_main — the public entry point invoked by main().
// ---------------------------------------------------------------------------
int cli_main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);

    if (args.empty()) {
        print_usage();
        return 0;
    }

    const std::string& first = args[0];
    if (first == "-h" || first == "--help") {
        print_usage();
        return 0;
    }
    if (first == "--version") {
        std::cout << "lock 1.0.0\n";
        return 0;
    }
    if (first == "--cli") {
        std::vector<std::string> rest(args.begin() + 1, args.end());
        return run_interactive(std::move(rest));
    }

    std::string cmd;
    size_t arg_offset = 0;
    if (first == "-c" || first == "--command") {
        if (args.size() < 2) {
            std::cerr << "error: -c requires a command\n";
            return 1;
        }
        cmd = args[1];
        arg_offset = 2;
    } else {
        cmd = first;
        arg_offset = 1;
    }

    if (cmd != "encrypt" && cmd != "decrypt" && cmd != "list") {
        std::cerr << "error: unknown command '" << cmd << "'\n";
        print_usage();
        return 1;
    }

    ParsedArgs pa = parse_args(args, arg_offset);
    if (!pa.error.empty()) {
        std::cerr << "error: " << pa.error << "\n";
        return 1;
    }
    if (pa.files.empty()) {
        std::cerr << "error: no input files specified\n";
        return 1;
    }

    // chunk_size is only meaningful for encrypt — decrypt uses the value
    // stored in the container header.
    if (cmd == "encrypt") {
        if (pa.chunk_size < 4096u) {
            std::cerr << "error: --chunk-size must be at least 4096\n";
            return 1;
        }
        if ((pa.chunk_size % (uint32_t)AES_BLOCK_SIZE) != 0u) {
            std::cerr << "error: --chunk-size must be a multiple of 16\n";
            return 1;
        }
    }

    PasswordMode mode = PasswordMode::Interactive;
    if (!pa.password_file.empty()) {
        mode = PasswordMode::FromFile;
    } else if (pa.password_env_var) {
        mode = PasswordMode::FromEnvironment;
    }

    if (cmd == "encrypt") {
        ProgressTracker tracker;
        EncryptCliArgs eargs;
        eargs.files         = pa.files;
        eargs.password_mode = mode;
        eargs.password_file = pa.password_file;
        eargs.no_safe       = pa.no_safe;
        eargs.jobs          = pa.jobs;
        eargs.output_dir    = pa.output_dir;
        eargs.chunk_size    = pa.chunk_size;
        eargs.verbose       = pa.verbose;
        eargs.quiet         = pa.quiet;
        return run_encrypt(eargs, tracker);
    }
    if (cmd == "decrypt") {
        ProgressTracker tracker;
        DecryptCliArgs dargs;
        dargs.files         = pa.files;
        dargs.password_mode = mode;
        dargs.password_file = pa.password_file;
        dargs.no_safe       = pa.no_safe;
        dargs.jobs          = pa.jobs;
        dargs.output_dir    = pa.output_dir;
        dargs.verbose       = pa.verbose;
        dargs.quiet         = pa.quiet;
        return run_decrypt(dargs, tracker);
    }
    return run_list(pa.files);
}

}  // namespace lock

// lock::cli — argv parsing, subcommand dispatch, and file-orchestration glue
// between the password acquirer, the KDF, the crypto core, and the progress
// tracker. main() (in main.cpp) delegates everything to cli_main().
#include <lock/cli.hpp>

#include <lock/compress.hpp>
#include <lock/constants.hpp>
#include <lock/container.hpp>
#include <lock/crypto.hpp>
#include <lock/errors.hpp>
#include <lock/i18n.hpp>
#include <lock/kdf.hpp>
#include <lock/memory.hpp>
#include <lock/progress.hpp>
#include <lock/safe.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace lock {

namespace {

// ---------------------------------------------------------------------------
// Helpers — emit "error: <msg>\n" / "warning: <msg>\n" with colour applied
// to the label so the user's eye lands on the severity first.
// ---------------------------------------------------------------------------
void emit_error(std::string_view msg) {
    std::cerr << color_error(tr(Str::Err_label)) << msg << "\n";
}

void emit_warn(std::string_view msg) {
    std::cerr << color_warn(tr(Str::Warn_label)) << msg << "\n";
}

// Case-insensitive comparison of two C strings so --lang EN / En / en match.
bool eq_ignore_case(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

struct ParsedArgs {
    std::vector<std::string> files;
    std::string password_file;
    bool password_env_var = false;
    bool no_safe          = false;
    uint32_t jobs         = 0;
    bool jobs_explicit    = false;
    std::string output_dir;
    uint32_t chunk_size   = (uint32_t)DEFAULT_CHUNK_SIZE;
    bool chunk_size_explicit = false;
    CompressionId compression      = CompressionId::NONE;
    int            compression_level = 3;
    bool verbose          = false;
    bool quiet            = false;
    bool auto_mode        = false;
    bool auto_seen        = false;
    std::string auto_dir;
    int32_t max_depth     = -1;
    std::string lang_str;
    bool     lang_seen    = false;
    bool     no_color      = false;
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
        pa.error = subst(tr(Str::Err_arg_requires_nonneg), flag_name);
        return false;
    }
    try {
        unsigned long long parsed = std::stoull(v);
        if (parsed < min_v || parsed > max_v) {
            pa.error = subst3(tr(Str::Err_arg_out_of_range),
                              flag_name,
                              std::to_string(min_v),
                              std::to_string(max_v));
            return false;
        }
        out = static_cast<uint32_t>(parsed);
        return true;
    } catch (const std::exception&) {
        pa.error = subst(tr(Str::Err_arg_requires_int), flag_name);
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
        if (parse_uint32(flag, value, 1u, 1024u, pa.jobs, pa)) {
            pa.jobs_explicit = true;
            return true;
        }
        return false;
    }
    if (flag == "--chunk-size") {
        if (parse_uint32(flag, value, 4096u,
                         static_cast<uint32_t>(1024u * 1024u * 16u),
                         pa.chunk_size, pa)) {
            pa.chunk_size_explicit = true;
            return true;
        }
        return false;
    }
    if (flag == "--compress") {
        if (value == "none") { pa.compression = CompressionId::NONE; return true; }
        if (value == "lz4")  { pa.compression = CompressionId::LZ4;  return true; }
        if (value == "zstd") { pa.compression = CompressionId::ZSTD; return true; }
        pa.error = subst(tr(Str::Err_arg_invalid_compress), value);
        return false;
    }
    if (flag == "--level") {
        try {
            long long L = std::stoll(value);
            if (L < 1 || L > 22) {
                pa.error = tr(Str::Err_level_range);
                return false;
            }
            pa.compression_level = static_cast<int>(L);
            return true;
        } catch (const std::exception&) {
            pa.error = subst(tr(Str::Err_arg_requires_int), flag);
            return false;
        }
    }
    if (flag == "--auto") {
        if (pa.auto_seen) {
            pa.error = tr(Str::Err_auto_repeat);
            return false;
        }
        pa.auto_mode = true;
        pa.auto_seen = true;
        pa.auto_dir  = value;
        return true;
    }
    if (flag == "--max-depth") {
        try {
            long long v = std::stoll(value);
            if (v < -1 || v > 65535) {
                pa.error = tr(Str::Err_max_depth_range);
                return false;
            }
            pa.max_depth = static_cast<int32_t>(v);
            return true;
        } catch (const std::exception&) {
            pa.error = subst(tr(Str::Err_arg_requires_int), flag);
            return false;
        }
    }
    if (flag == "--lang") {
        if (!eq_ignore_case(value, "en") && !eq_ignore_case(value, "zh")) {
            pa.error = subst(tr(Str::Err_lang_invalid), value);
            return false;
        }
        pa.lang_str  = value;
        pa.lang_seen = true;
        return true;
    }
    pa.error = subst(tr(Str::Err_arg_unknown), flag);
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
        if (tok == "--no-color") {
            pa.no_color = true;
            continue;
        }
        if (tok == "-pev" || tok == "--password-env-var") {
            pa.password_env_var = true;
            continue;
        }
        if (tok == "-z") {
            pa.compression = CompressionId::ZSTD;
            continue;
        }
        if (tok == "--fast") {
            pa.compression = CompressionId::LZ4;
            continue;
        }

        if (tok == "-p" || tok == "--password-file" ||
            tok == "-j" || tok == "--jobs" ||
            tok == "-o" || tok == "--output-dir" ||
            tok == "--chunk-size" ||
            tok == "--compress" || tok == "--level" ||
            tok == "--auto" || tok == "--max-depth" ||
            tok == "--lang") {
            if (i + 1 >= args.size()) {
                pa.error = subst(tr(Str::Err_arg_value_required), tok);
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
                flag_name == "--chunk-size" ||
                flag_name == "--compress" || flag_name == "--level" ||
                flag_name == "--auto" || flag_name == "--max-depth" ||
                flag_name == "--lang") {
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
            pa.error = subst(tr(Str::Err_arg_unknown), tok);
            break;
        }
        pa.files.push_back(tok);
    }

    return pa;
}

// ---------------------------------------------------------------------------
// Grouped help — emitted in the active UI language.
// ---------------------------------------------------------------------------
void print_usage() {
    std::cout << tr(Str::Help_usage_line)
              << "\n"
              << tr(Str::Help_usage_desc)
              << "\n"
              << tr(Str::Help_usage_cmd)
              << "\n"
              << tr(Str::Help_cmd_encrypt)
              << tr(Str::Help_cmd_decrypt)
              << tr(Str::Help_cmd_list)
              << "\n"
              << tr(Str::Help_grp_common)
              << tr(Str::Help_opt_password_file)
              << tr(Str::Help_opt_password_env)
              << tr(Str::Help_opt_no_safe)
              << tr(Str::Help_opt_jobs)
              << tr(Str::Help_opt_output_dir)
              << tr(Str::Help_opt_verbose)
              << tr(Str::Help_opt_quiet)
              << tr(Str::Help_opt_lang)
              << tr(Str::Help_opt_no_color)
              << tr(Str::Help_opt_version)
              << tr(Str::Help_opt_help)
              << "\n"
              << tr(Str::Help_grp_encrypt)
              << tr(Str::Help_opt_chunk_size)
              << tr(Str::Help_opt_compress)
              << tr(Str::Help_opt_compress_z)
              << tr(Str::Help_opt_compress_fast)
              << tr(Str::Help_opt_level)
              << tr(Str::Help_opt_auto)
              << tr(Str::Help_opt_max_depth)
              << "\n"
              << tr(Str::Help_grp_decrypt)
              << tr(Str::Help_decrypt_note)
              << "\n"
              << tr(Str::Help_grp_examples)
              << tr(Str::Help_example_1)
              << tr(Str::Help_example_2)
              << tr(Str::Help_example_3)
              << tr(Str::Help_example_4);
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

std::string rel_path_under(const std::filesystem::path& root,
                          const std::filesystem::path& p) {
    std::error_code rec_ec;
    std::filesystem::path r = std::filesystem::relative(p, root, rec_ec);
    if (rec_ec) {
        return std::string();
    }
    std::string s = r.string();
    if (s == ".") {
        return std::string();
    }
    return s;
}

int collect_encrypt_inputs(const std::string& auto_dir_in,
                           int32_t max_depth,
                           std::vector<std::pair<std::string,
                                                 std::string>>& out_files) {
    std::error_code ec;
    std::filesystem::path root = std::filesystem::weakly_canonical(
        std::filesystem::path(auto_dir_in), ec);
    if (ec) {
        return 1;
    }
    using E = std::pair<std::filesystem::path, int>;
    std::deque<E> q;
    q.push_back({root, 0});

    while (!q.empty()) {
        E cur = q.front();
        q.pop_front();
        const std::filesystem::path& cur_dir = cur.first;
        int cur_depth = cur.second;

        std::error_code iter_ec;
        std::filesystem::directory_iterator it(cur_dir,
            std::filesystem::directory_options::skip_permission_denied,
            iter_ec);
        if (iter_ec) {
            return 1;
        }
        for (auto it_end = std::filesystem::directory_iterator();
             it != it_end; it.increment(iter_ec)) {
            if (iter_ec) {
                return 1;
            }
            const std::filesystem::directory_entry& de = *it;
            std::error_code st_ec;
            std::filesystem::path p = de.path();
            if (de.is_symlink(st_ec)) {
                continue;
            }
            if (de.is_regular_file(st_ec)) {
                std::string name = p.filename().string();
                if (name.size() >= 7u &&
                    name.compare(name.size() - 7u, 7u, LOCKED_EXTENSION) == 0) {
                    continue;
                }
                std::string rel = rel_path_under(root, p);
                out_files.emplace_back(p.string(), rel);
            } else if (de.is_directory(st_ec)) {
                if (max_depth == -1 || cur_depth + 1 <= max_depth) {
                    std::error_code st2_ec;
                    std::filesystem::path canon = std::filesystem::canonical(p, st2_ec);
                    if (st2_ec) {
                        canon = p;
                    }
                    q.push_back({canon, cur_depth + 1});
                }
            }
        }
    }
    return 0;
}

int collect_decrypt_inputs(const std::string& auto_dir_in,
                           int32_t max_depth,
                           std::vector<std::pair<std::string,
                                                 std::string>>& out_files) {
    std::error_code ec;
    std::filesystem::path root = std::filesystem::weakly_canonical(
        std::filesystem::path(auto_dir_in), ec);
    if (ec) {
        return 1;
    }
    using E = std::pair<std::filesystem::path, int>;
    std::deque<E> q;
    q.push_back({root, 0});

    while (!q.empty()) {
        E cur = q.front();
        q.pop_front();
        const std::filesystem::path& cur_dir = cur.first;
        int cur_depth = cur.second;

        std::error_code iter_ec;
        std::filesystem::directory_iterator it(cur_dir,
            std::filesystem::directory_options::skip_permission_denied,
            iter_ec);
        if (iter_ec) {
            return 1;
        }
        for (auto it_end = std::filesystem::directory_iterator();
             it != it_end; it.increment(iter_ec)) {
            if (iter_ec) {
                return 1;
            }
            const std::filesystem::directory_entry& de = *it;
            std::error_code st_ec;
            std::filesystem::path p = de.path();
            if (de.is_symlink(st_ec)) {
                continue;
            }
            if (de.is_regular_file(st_ec)) {
                std::string name = p.filename().string();
                if (name.size() < 7u ||
                    name.compare(name.size() - 7u, 7u, LOCKED_EXTENSION) != 0) {
                    continue;
                }
                std::string rel = rel_path_under(root, p);
                out_files.emplace_back(p.string(), rel);
            } else if (de.is_directory(st_ec)) {
                if (max_depth == -1 || cur_depth + 1 <= max_depth) {
                    std::error_code st2_ec;
                    std::filesystem::path canon = std::filesystem::canonical(p, st2_ec);
                    if (st2_ec) {
                        canon = p;
                    }
                    q.push_back({canon, cur_depth + 1});
                }
            }
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Decide in what subcommand context a directory scan-failure / empty-result
// message should be tagged. Used below to localise the "Encrypting"/"Decrypting"
// progress label.
// ---------------------------------------------------------------------------
enum class OpTag { Encrypt, Decrypt };

const char* op_progress_prefix(OpTag op) {
    return (op == OpTag::Encrypt) ? tr(Str::Progress_file_label_enc)
                                  : tr(Str::Progress_file_label_dec);
}

// ---------------------------------------------------------------------------
// Encrypt orchestration.
// ---------------------------------------------------------------------------
struct EncryptCliArgs {
    std::vector<std::string> files;
    PasswordMode password_mode = PasswordMode::Interactive;
    std::string password_file;
    bool no_safe          = false;
    uint32_t jobs         = 0;
    bool jobs_explicit    = false;
    std::string output_dir;
    uint32_t chunk_size   = (uint32_t)DEFAULT_CHUNK_SIZE;
    bool chunk_size_explicit = false;
    CompressionId compression      = CompressionId::NONE;
    int            compression_level = 3;
    bool verbose          = false;
    bool quiet            = false;
    bool   auto_mode      = false;
    std::string auto_dir;
    int32_t max_depth     = -1;
};

ExitCode run_encrypt(const EncryptCliArgs& args, ProgressTracker& tracker) {
    PasswordRequest req;
    req.mode     = args.password_mode;
    req.file_path = args.password_file;
    req.no_safe  = args.no_safe;
    PasswordResult pw;
    try {
        pw = acquire_password(req);
    } catch (const LockError&) {
        throw;
    } catch (const std::exception& e) {
        std::string what = e.what();
        if (what.find("HMAC") != std::string::npos || what.find("GCM") != std::string::npos ||
            what.find("scrypt") != std::string::npos) {
            throw LockError(ExitCode::Crypto, what);
        }
        throw LockError(ExitCode::Arg, what);
    }
    if (!pw.warn.empty() && args.verbose) {
        emit_warn(pw.warn);
    }

    auto salt = generate_salt();
    auto iv  = random_bytes(IV_SIZE);
    if (iv.size() < IV_SIZE) {
        throw LockError(ExitCode::Crypto, tr(Str::Err_RAND_short));
    }
    std::array<unsigned char, IV_SIZE> base_iv{};
    std::copy_n(iv.begin(), IV_SIZE, base_iv.begin());

    ScryptParams sp{};
    KeyMaterial km;
    try {
        km = derive_key_scrypt(pw.password, salt, sp);
    } catch (const std::exception& e) {
        std::string what = e.what();
        if (what.find("scrypt") != std::string::npos ||
            what.find("RAND_bytes") != std::string::npos) {
            throw LockError(ExitCode::Crypto, what);
        }
        throw LockError(ExitCode::Internal, what);
    }

    std::vector<std::string> input_files;
    std::vector<std::filesystem::path> output_paths;

    if (args.auto_mode) {
        std::vector<std::pair<std::string, std::string>> collected;
        if (collect_encrypt_inputs(args.auto_dir, args.max_depth, collected) != 0) {
            emit_error(subst(tr(Str::Err_scan_auto_dir), args.auto_dir));
            return ExitCode::Io;
        }
        if (collected.empty()) {
            emit_error(subst(tr(Str::Err_no_eligible_files), args.auto_dir));
            return ExitCode::Arg;
        }
        input_files.reserve(collected.size());
        output_paths.reserve(collected.size());
        for (auto& [in_p, rel] : collected) {
            std::filesystem::path in_path(in_p);
            std::filesystem::path out_path;
            if (rel.empty()) {
                out_path = std::filesystem::path(args.output_dir) /
                           in_path.filename();
            } else {
                std::filesystem::path mirror =
                    std::filesystem::path(args.output_dir) / rel;
                out_path = mirror;
                std::filesystem::path parent = mirror.parent_path();
                std::error_code mk_ec;
                std::filesystem::create_directories(parent, mk_ec);
                if (mk_ec && !std::filesystem::is_directory(parent, mk_ec)) {
                    emit_error(subst2(tr(Str::Err_output_dir_create),
                                       parent.string(), mk_ec.message()));
                    return ExitCode::Io;
                }
            }
            out_path += LOCKED_EXTENSION;
            input_files.push_back(in_p);
            output_paths.push_back(std::move(out_path));
        }
    } else {
        input_files = args.files;
        output_paths.reserve(args.files.size());
        for (const auto& input : args.files) {
            std::filesystem::path output_path =
                args.output_dir.empty()
                    ? std::filesystem::path(input).concat(LOCKED_EXTENSION)
                    : std::filesystem::path(args.output_dir) /
                          (std::filesystem::path(input).filename().string() +
                           LOCKED_EXTENSION);
            output_paths.push_back(std::move(output_path));
        }
    }

    if (!args.auto_mode && !args.output_dir.empty()) {
        std::error_code mk_ec;
        std::filesystem::create_directories(args.output_dir, mk_ec);
        if (mk_ec &&
            !std::filesystem::is_directory(args.output_dir, mk_ec)) {
            emit_error(subst2(tr(Str::Err_output_dir_create),
                               args.output_dir, mk_ec.message()));
            return ExitCode::Io;
        }
    }

    for (const auto& output_path : output_paths) {
        if (std::error_code ec; std::filesystem::exists(output_path, ec)) {
            emit_error(subst(tr(Str::Err_output_exists),
                              output_path.string()));
            return ExitCode::Io;
        }
    }

    if (!args.quiet) {
        tracker.start(input_files.size());
    }

    lock::memory_status ms = lock::detect_memory();
    unsigned hw = std::thread::hardware_concurrency();
    if (hw == 0u) {
        hw = 1u;
    }

    std::vector<std::thread> workers;
    workers.reserve(input_files.size());
    std::atomic<size_t> files_done{0};
    std::mutex error_mutex;
    std::optional<std::string> first_error;

    for (size_t i = 0; i < input_files.size(); ++i) {
        const std::string& input    = input_files[i];
        const std::filesystem::path& output_path = output_paths[i];

        size_t file_size = static_cast<size_t>(
            std::filesystem::file_size(input));
        size_t cs = lock::recommend_chunk_size(
            ms.available_bytes,
            args.chunk_size_explicit ? static_cast<size_t>(args.chunk_size) : 0u,
            file_size);
        uint32_t chunk_size_u32 =
            (cs > static_cast<size_t>(UINT32_MAX))
                ? UINT32_MAX
                : static_cast<uint32_t>(cs);

        unsigned jobs = lock::recommend_jobs(
            args.jobs_explicit ? static_cast<unsigned>(args.jobs) : 0u,
            ms.available_bytes, cs, hw);

        if (args.verbose) {
            std::cerr << tr(Str::Verbose_memory_line)
                      << (ms.available_bytes / 1024 / 1024)
                      << " MiB; chunk_size=" << (cs / 1024) << " KiB; jobs="
                      << jobs
                      << (args.chunk_size_explicit ? " (chunk_size explicit)" : "")
                      << (args.jobs_explicit ? " (jobs explicit)" : "")
                      << "\n";
        }

        uintmax_t chunks =
            (static_cast<uintmax_t>(file_size) + chunk_size_u32 - 1u) /
            chunk_size_u32;
        size_t total_chunks = static_cast<size_t>(chunks);

        if (!args.quiet) {
            std::string prefix = std::string(op_progress_prefix(OpTag::Encrypt)) +
                                 std::filesystem::path(input).filename().string();
            tracker.start_file(i, prefix, total_chunks);
        }

        workers.emplace_back(
            [&, i, input, output_path,
             file_key    = km.file_key,
             hmac_key    = km.hmac_key,
             salt, base_iv,
             chunk_size_u32, jobs]() {
                EncryptOptions opts;
                opts.file_key    = file_key;
                opts.hmac_key    = hmac_key;
                opts.salt        = salt;
                opts.base_iv     = base_iv;
                opts.kdf_N       = static_cast<uint32_t>(SCRYPT_DEFAULT_N);
                opts.kdf_r       = SCRYPT_DEFAULT_R;
                opts.kdf_p       = SCRYPT_DEFAULT_P;
                opts.chunk_size  = chunk_size_u32;
                opts.num_threads = jobs;
                opts.compression       = args.compression;
                opts.compression_level = args.compression_level;
                opts.progress    = args.quiet
                                       ? ProgressCallback{}
                                       : tracker.make_callback(i,
                                           static_cast<size_t>(chunk_size_u32));
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
        std::string msg = *first_error;
        emit_error(msg);
        return ExitCode::Io;
    }
    return ExitCode::Ok;
}

// ---------------------------------------------------------------------------
// Decrypt orchestration.
// ---------------------------------------------------------------------------
struct DecryptCliArgs {
    std::vector<std::string> files;
    PasswordMode password_mode = PasswordMode::Interactive;
    std::string password_file;
    bool no_safe          = false;
    uint32_t jobs         = 0;
    bool jobs_explicit    = false;
    std::string output_dir;
    uint32_t chunk_size   = (uint32_t)DEFAULT_CHUNK_SIZE;
    bool chunk_size_explicit = false;
    bool verbose          = false;
    bool quiet            = false;
    bool   auto_mode      = false;
    std::string auto_dir;
    int32_t max_depth     = -1;
};

ExitCode run_decrypt(const DecryptCliArgs& args, ProgressTracker& tracker) {
    PasswordRequest req;
    req.mode     = args.password_mode;
    req.file_path = args.password_file;
    req.no_safe  = args.no_safe;
    PasswordResult pw;
    try {
        pw = acquire_password(req);
    } catch (const LockError&) {
        throw;
    } catch (const std::exception& e) {
        std::string what = e.what();
        if (what.find("HMAC") != std::string::npos || what.find("GCM") != std::string::npos ||
            what.find("scrypt") != std::string::npos) {
            throw LockError(ExitCode::Crypto, what);
        }
        throw LockError(ExitCode::Arg, what);
    }
    if (!pw.warn.empty() && args.verbose) {
        emit_warn(pw.warn);
    }

    std::vector<std::string> input_files;
    std::vector<std::string> target_subdirs;

    if (args.auto_mode) {
        std::vector<std::pair<std::string, std::string>> collected;
        if (collect_decrypt_inputs(args.auto_dir, args.max_depth, collected) != 0) {
            emit_error(subst(tr(Str::Err_scan_auto_dir), args.auto_dir));
            return ExitCode::Io;
        }
        if (collected.empty()) {
            emit_error(subst(tr(Str::Err_no_eligible_files), args.auto_dir));
            return ExitCode::Arg;
        }
        input_files.reserve(collected.size());
        target_subdirs.reserve(collected.size());
        constexpr size_t kExtLen = 7;
        for (auto& [in_p, rel] : collected) {
            std::string sub = rel;
            if (sub.size() >= kExtLen &&
                sub.compare(sub.size() - kExtLen, kExtLen,
                            LOCKED_EXTENSION) == 0) {
                sub = sub.substr(0, sub.size() - kExtLen);
            }
            std::filesystem::path p(sub);
            std::string parent = p.parent_path().string();
            if (parent == "." || parent.empty()) {
                parent.clear();
            }
            input_files.push_back(in_p);
            target_subdirs.push_back(std::move(parent));
        }
    } else {
        input_files = args.files;
        target_subdirs.resize(args.files.size());
        if (!args.output_dir.empty()) {
            std::error_code mk_ec;
            std::filesystem::create_directories(args.output_dir, mk_ec);
            if (mk_ec &&
                !std::filesystem::is_directory(args.output_dir, mk_ec)) {
                emit_error(subst2(tr(Str::Err_output_dir_create),
                                   args.output_dir, mk_ec.message()));
                return ExitCode::Io;
            }
        }
    }

    for (const auto& input : input_files) {
        if (!HeaderReader::is_locked_file(input)) {
            emit_error(subst(tr(Str::Err_not_locked), input));
            return ExitCode::Io;
        }
    }

    if (!args.quiet) {
        tracker.start(input_files.size());
    }

    lock::memory_status ms = lock::detect_memory();
    unsigned hw = std::thread::hardware_concurrency();
    if (hw == 0u) {
        hw = 1u;
    }

    std::vector<std::thread> workers;
    workers.reserve(input_files.size());
    std::atomic<size_t> files_done{0};
    std::mutex error_mutex;
    std::optional<std::string> first_error;

    for (size_t i = 0; i < input_files.size(); ++i) {
        const std::string& input = input_files[i];

        size_t file_size = static_cast<size_t>(
            std::filesystem::file_size(input));
        size_t cs = lock::recommend_chunk_size(
            ms.available_bytes,
            args.chunk_size_explicit ? static_cast<size_t>(args.chunk_size) : 0u,
            file_size);
        unsigned jobs = lock::recommend_jobs(
            args.jobs_explicit ? static_cast<unsigned>(args.jobs) : 0u,
            ms.available_bytes, cs, hw);

        if (args.verbose) {
            std::cerr << tr(Str::Verbose_memory_line)
                      << (ms.available_bytes / 1024 / 1024)
                      << " MiB; chunk_size=" << (cs / 1024) << " KiB; jobs="
                      << jobs
                      << (args.chunk_size_explicit ? " (chunk_size explicit)" : "")
                      << (args.jobs_explicit ? " (jobs explicit)" : "")
                      << "\n";
        }

        workers.emplace_back(
            [&, i, input, password = pw.password, jobs]() {
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
                        constexpr size_t kExtLen = 7;
                        std::string fn =
                            std::filesystem::path(input).filename().string();
                        if (fn.size() >= kExtLen &&
                            fn.compare(fn.size() - kExtLen, kExtLen,
                                        LOCKED_EXTENSION) == 0) {
                            original_name = fn.substr(0, fn.size() - kExtLen);
                        } else {
                            original_name = "decrypted.dat";
                        }
                    }

                    std::filesystem::path safe_name =
                        std::filesystem::path(original_name).filename();
                    if (safe_name.empty()) {
                        safe_name = "decrypted.dat";
                    }

                    std::filesystem::path out_leaf_dir;
                    if (args.auto_mode) {
                        const std::string& tsub = target_subdirs[i];
                        if (tsub.empty()) {
                            out_leaf_dir = std::filesystem::path(args.output_dir);
                        } else {
                            out_leaf_dir =
                                std::filesystem::path(args.output_dir) / tsub;
                        }
                        std::error_code mk_ec;
                        std::filesystem::create_directories(out_leaf_dir, mk_ec);
                        if (mk_ec &&
                            !std::filesystem::is_directory(out_leaf_dir, mk_ec)) {
                            throw std::runtime_error(
                                "cannot create output directory '" +
                                out_leaf_dir.string() + "': " + mk_ec.message());
                        }
                    } else if (args.output_dir.empty()) {
                        out_leaf_dir = std::filesystem::path(input).parent_path();
                    } else {
                        out_leaf_dir = std::filesystem::path(args.output_dir);
                    }

                    std::filesystem::path output_path = out_leaf_dir / safe_name;

                    if (std::error_code ec;
                        std::filesystem::exists(output_path, ec)) {
                        throw std::runtime_error(
                            "'" + output_path.string() + "' already exists");
                    }

                    uintmax_t header_cs = static_cast<uintmax_t>(header.chunk_size);
                    uintmax_t chunks =
                        (header.original_size + header_cs - 1) / header_cs;
                    size_t total_chunks = static_cast<size_t>(chunks);

                    if (!args.quiet) {
                        std::string prefix =
                            std::string(op_progress_prefix(OpTag::Decrypt)) +
                            safe_name.string();
                        tracker.start_file(i, prefix, total_chunks);
                    }

                    DecryptOptions opts;
                    opts.file_key    = km.file_key;
                    opts.hmac_key    = km.hmac_key;
                    opts.num_threads = jobs;
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
        std::string what = *first_error;
        emit_error(what);
        if (what.find("HMAC") != std::string::npos ||
            what.find("GCM") != std::string::npos ||
            what.find("scrypt") != std::string::npos) {
            return ExitCode::Crypto;
        }
        if (what.find("does not exist") != std::string::npos ||
            what.find("already exists") != std::string::npos ||
            what.find("cannot open") != std::string::npos ||
            what.find("cannot create output directory") != std::string::npos ||
            what.find("filesystem error") != std::string::npos ||
            what.find("cannot get file size") != std::string::npos) {
            return ExitCode::Io;
        }
        return ExitCode::Internal;
    }
    return ExitCode::Ok;
}

// ---------------------------------------------------------------------------
// List.
// ---------------------------------------------------------------------------
ExitCode run_list(const std::vector<std::string>& files) {
    for (const auto& input : files) {
        std::cout << tr(Str::List_file_header) << input << "\n";
        if (!HeaderReader::is_locked_file(input)) {
            std::cout << tr(Str::List_not_locked) << "\n\n";
            continue;
        }
        try {
            std::ifstream in(input, std::ios::binary);
            FileHeader h = HeaderReader::read(in);

            std::cout << tr(Str::List_field_magic);
            std::cout << tr(Str::List_field_version) << h.version << "\n";
            std::cout << tr(Str::List_field_algorithm)
                      << std::hex << h.algorithm_id << std::dec << ")\n";
            std::cout << tr(Str::List_field_kdf)
                      << h.kdf_N << " r=" << h.kdf_r << " p=" << h.kdf_p << ")\n";
            std::cout << tr(Str::List_field_salt)
                      << to_hex(h.salt.data(), h.salt.size()) << "\n";
            std::cout << tr(Str::List_field_base_iv)
                      << to_hex(h.base_iv.data(), h.base_iv.size()) << "\n";
            std::cout << tr(Str::List_field_original_size)
                      << h.original_size << " bytes\n";
            std::cout << tr(Str::List_field_chunk_size)
                      << h.chunk_size << " bytes\n";
            std::cout << tr(Str::List_field_chunk_count) << h.chunk_count << "\n";
            std::cout << tr(Str::List_field_compression)
                      << compression_id_name(static_cast<CompressionId>(h.compression_id)) << "\n";
            std::cout << tr(Str::List_field_stored_size)
                      << h.stored_size << " bytes\n";
            std::cout << tr(Str::List_field_filename_len)
                      << h.filename_len << "\n";
            std::cout << tr(Str::List_field_data_offset)
                      << h.data_offset() << " bytes\n";
            std::uintmax_t total_size = std::filesystem::file_size(input);
            std::cout << tr(Str::List_field_file_size)
                      << total_size << " bytes\n";
            std::uintmax_t overhead = (h.original_size >= total_size)
                                          ? 0
                                          : (total_size - h.original_size);
            double denom = (total_size == 0) ? 1.0
                                             : static_cast<double>(total_size);
            std::cout << tr(Str::List_field_overhead)
                      << overhead << " bytes ("
                      << std::fixed << std::setprecision(3)
                      << (100.0 * static_cast<double>(overhead) / denom)
                      << "%)\n";
        } catch (const std::exception& e) {
            std::cout << tr(Str::List_field_error) << e.what() << "\n";
        }
        std::cout << "\n";
    }
    return ExitCode::Ok;
}

// ---------------------------------------------------------------------------
// Interactive REPL.
// ---------------------------------------------------------------------------
ExitCode run_interactive(std::vector<std::string> /*rest*/) {
    std::cerr << tr(Str::Repl_banner);
    std::cerr << tr(Str::Repl_commands_hint);

    std::string line;
    while (std::cerr << tr(Str::Repl_prompt) && std::getline(std::cin, line)) {
        size_t first_nonspace = line.find_first_not_of(" \t");
        if (first_nonspace == std::string::npos) {
            continue;
        }
        line = line.substr(first_nonspace);

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        if (cmd == "quit" || cmd == "exit" || cmd == "q") {
            return ExitCode::Ok;
        }
        if (cmd != "encrypt" && cmd != "decrypt" && cmd != "list") {
            std::cerr << tr(Str::Repl_unknown_command_pre) << cmd
                      << (I18n::current() == Lang::Zh
                              ? tr(Str::Repl_unknown_command_suf_zh)
                              : tr(Str::Repl_unknown_command_suf_en));
            continue;
        }

        std::vector<std::string> files;
        std::string tok;
        while (iss >> tok) {
            files.push_back(tok);
        }
        while (true) {
            std::cerr << tr(Str::Repl_file_prompt);
            std::string p;
            if (!std::getline(std::cin, p)) {
                return ExitCode::Ok;
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
            std::cerr << tr(Str::Repl_no_files);
            continue;
        }

        if (cmd == "list") {
            (void)run_list(files);
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
            eargs.compression       = CompressionId::NONE;
            eargs.compression_level = 3;
            try {
                (void)run_encrypt(eargs, etracker);
            } catch (const LockError& e) {
                emit_error(e.what());
            } catch (const std::exception& e) {
                emit_error(e.what());
            }
        } else {
            DecryptCliArgs dargs;
            dargs.files         = files;
            dargs.password_mode = PasswordMode::Interactive;
            dargs.jobs          = 0;
            dargs.quiet         = true;
            try {
                (void)run_decrypt(dargs, etracker);
            } catch (const LockError& e) {
                emit_error(e.what());
            } catch (const std::exception& e) {
                emit_error(e.what());
            }
        }
    }
    return ExitCode::Ok;
}

// Map an untyped std::runtime_error (raised from outside cli.cpp, e.g. from
// crypto.cpp's I/O or OpenSSL wrappers) onto an ExitCode by inspecting the
// message.  This is the only path that uses substring classification; all
// code paths that originate in cli.cpp / safe.cpp raise a LockError directly
// so a "what" keyword match isn't needed there.
ExitCode classify_runtime_error(const std::string& what) {
    if (what.find("HMAC") != std::string::npos ||
        what.find("GCM") != std::string::npos ||
        what.find("scrypt") != std::string::npos ||
        what.find("RAND_bytes") != std::string::npos) {
        return ExitCode::Crypto;
    }
    if (what.find("does not exist") != std::string::npos ||
        what.find("already exists") != std::string::npos ||
        what.find("cannot open") != std::string::npos ||
        what.find("cannot create output directory") != std::string::npos ||
        what.find("filesystem error") != std::string::npos ||
        what.find("cannot get file size") != std::string::npos) {
        return ExitCode::Io;
    }
    return ExitCode::Internal;
}

// ---------------------------------------------------------------------------
// cli_main — public entry point invoked by main().
// ---------------------------------------------------------------------------
}  // namespace (anonymous)

int cli_main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);

    if (args.empty()) {
        print_usage();
        return static_cast<int>(ExitCode::Ok);
    }

    // --help / --version / --cli may appear after a global flag (e.g.
    // '--lang zh --help'): scan the whole args vector for the first one and
    // short-circuit.
    auto find_first_special = [&]() -> int {
        for (size_t k = 0; k < args.size(); ++k) {
            const std::string& tok = args[k];
            if (tok == "-h" || tok == "--help" ||
                tok == "--version" || tok == "--cli") {
                return static_cast<int>(k);
            }
            if (tok == "--lang" && k + 1 < args.size()) { ++k; }
        }
        return -1;
    };

    Lang env_lang = detect_lang_from_env();
    I18n::init(env_lang);
    enable_color_if_tty();

    int special_idx = find_first_special();
    if (special_idx >= 0) {
        const std::string& special = args[static_cast<size_t>(special_idx)];
        // honour --lang appearing BEFORE the special command.
        for (size_t k = 0; k < static_cast<size_t>(special_idx); ++k) {
            if (args[k] == "--lang" && k + 1 < args.size()) {
                const std::string& v = args[k + 1];
                if (eq_ignore_case(v, "zh")) {
                    I18n::init(Lang::Zh);
                } else if (eq_ignore_case(v, "en")) {
                    I18n::init(Lang::En);
                }
                ++k;
            } else if (args[k].rfind("--lang=", 0) == 0) {
                std::string v = args[k].substr(7);
                if (eq_ignore_case(v, "zh")) I18n::init(Lang::Zh);
                else if (eq_ignore_case(v, "en")) I18n::init(Lang::En);
            }
        }

        if (special == "-h" || special == "--help") {
            print_usage();
            return static_cast<int>(ExitCode::Ok);
        }
        if (special == "--version") {
            std::cout << tr(Str::Version_line) << "\n";
            return static_cast<int>(ExitCode::Ok);
        }
        if (special == "--cli") {
            std::vector<std::string> rest;
            for (size_t k = 0; k < args.size(); ++k) {
                if (k == static_cast<size_t>(special_idx)) continue;
                rest.push_back(args[k]);
            }
            ExitCode rc = ExitCode::Internal;
            try {
                rc = run_interactive(std::move(rest));
            } catch (const LockError& e) {
                emit_error(e.what());
                rc = e.code();
            } catch (const std::exception& e) {
                emit_error(e.what());
                rc = classify_runtime_error(e.what());
            }
            return static_cast<int>(rc);
        }
    }

    std::string cmd;
    size_t arg_offset = 0;
    {
        size_t i = 0;
        bool want_cmd = true;
        while (i < args.size() && want_cmd) {
            const std::string& tok = args[i];
            if (tok == "-v" || tok == "--verbose" ||
                tok == "-q" || tok == "--quiet" ||
                tok == "--no-color") {
                ++i;
                continue;
            }
            if (tok == "--lang" && i + 1 < args.size()) {
                i += 2;
                continue;
            }
            want_cmd = false;
            break;
        }

        // Reorder args so any global flags interleaved before the
        // subcommand land AFTER it — parse_args expects positional
        // globals after the subcommand.  This keeps a single parse path.
        auto reorder = [&](size_t sub_pos, const std::string& sub) {
            std::vector<std::string> rebuilt;
            rebuilt.reserve(args.size());
            rebuilt.push_back(sub);
            for (size_t k = 0; k < sub_pos; ++k) rebuilt.push_back(args[k]);
            for (size_t k = sub_pos + 1; k < args.size(); ++k) rebuilt.push_back(args[k]);
            args.swap(rebuilt);
        };

        if (i < args.size() && (args[i] == "-c" || args[i] == "--command")) {
            if (i + 1 >= args.size()) {
                emit_error(tr(Str::Err_arg_requires_command));
                return static_cast<int>(ExitCode::Arg);
            }
            cmd = args[i + 1];
            reorder(i + 1, cmd);
            // Strip the "-c" entry itself: parse_args must skip just `cmd`.
            // rebuild removed "-c cmd" by leaving only the post-prefix list:
            std::vector<std::string> stripped;
            stripped.reserve(args.size() - 1);
            stripped.push_back(cmd);
            for (size_t k = 2; k < args.size(); ++k) stripped.push_back(args[k]);
            args.swap(stripped);
            arg_offset = 1;
        } else if (i < args.size()) {
            cmd = args[i];
            reorder(i, cmd);
            arg_offset = 1;
        } else {
            cmd = args[0];
            arg_offset = 1;
        }
    }

    if (cmd != "encrypt" && cmd != "decrypt" && cmd != "list") {
        emit_error(subst(tr(Str::Err_unknown_cmd), cmd));
        print_usage();
        return static_cast<int>(ExitCode::Arg);
    }

    // Pre-pass: if any --lang <supported> appears in args, switch I18n now so
    // parse_args error messages use the user's chosen language. A second
    // --lang with an unsupported value still fails validation in parse_args.
    for (size_t k = arg_offset; k < args.size(); ++k) {
        std::string v;
        if (k + 1 < args.size() && args[k] == "--lang") {
            v = args[k + 1];
        } else if (args[k].rfind("--lang=", 0) == 0) {
            v = args[k].substr(7);
        } else {
            continue;
        }
        if (eq_ignore_case(v, "zh")) {
            I18n::init(Lang::Zh);
        } else if (eq_ignore_case(v, "en")) {
            I18n::init(Lang::En);
        }
        break;
    }

    ParsedArgs pa = parse_args(args, arg_offset);
    // Apply --no-color BEFORE any further error message is emitted.
    if (pa.no_color) {
        disable_color();
    }
    // --lang overrides the env-detected language. We must do this AFTER
    // parse_args so an invalid value lands on the same error path; but for
    // a valid override we want subsequent emit_error calls to use the new
    // language, so re-initialise I18n before checking pa.error.
    if (pa.lang_seen) {
        if (eq_ignore_case(pa.lang_str, "zh")) {
            I18n::init(Lang::Zh);
        } else {
            I18n::init(Lang::En);
        }
    }
    if (!pa.error.empty()) {
        emit_error(pa.error);
        return static_cast<int>(ExitCode::Arg);
    }

    if (pa.verbose) {
        EnvLangSource src = probe_env_lang_source();
        const char* a_env = (src.detected == Lang::Zh) ? "zh" : "en";
        const char* a_eff = (I18n::current()    == Lang::Zh) ? "zh" : "en";
        std::cerr << tr(Str::Verbose_lang_detected)
                  << a_env << " effective=" << a_eff << " (env: ";
        if (src.var_name[0] == '\0') {
            std::cerr << "unset";
        } else {
            std::cerr << src.var_name << "=" << src.value;
        }
        std::cerr << ")\n";
    }

    if (pa.auto_mode && cmd == "list") {
        emit_error(tr(Str::Err_auto_with_list));
        return static_cast<int>(ExitCode::Arg);
    }
    if (!pa.auto_mode && pa.max_depth != -1) {
        emit_error(tr(Str::Err_max_depth_no_auto));
        return static_cast<int>(ExitCode::Arg);
    }
    if (pa.auto_mode) {
        if (!pa.files.empty()) {
            emit_error(tr(Str::Err_auto_with_positional));
            return static_cast<int>(ExitCode::Arg);
        }
        std::error_code dir_ec;
        if (!std::filesystem::is_directory(pa.auto_dir, dir_ec)) {
            emit_error(subst(tr(Str::Err_auto_no_dir), pa.auto_dir));
            return static_cast<int>(ExitCode::Arg);
        }
        if (pa.output_dir.empty()) {
            emit_error(tr(Str::Err_auto_no_output));
            return static_cast<int>(ExitCode::Arg);
        }
    } else {
        if (pa.files.empty()) {
            emit_error(tr(Str::Err_no_input_files));
            return static_cast<int>(ExitCode::Arg);
        }
    }

    if (cmd == "encrypt") {
        if (pa.chunk_size < 4096u) {
            emit_error(tr(Str::Err_chunk_size_min));
            return static_cast<int>(ExitCode::Arg);
        }
        if ((pa.chunk_size % (uint32_t)AES_BLOCK_SIZE) != 0u) {
            emit_error(tr(Str::Err_chunk_size_mod));
            return static_cast<int>(ExitCode::Arg);
        }
    }

    PasswordMode mode = PasswordMode::Interactive;
    if (!pa.password_file.empty()) {
        mode = PasswordMode::FromFile;
    } else if (pa.password_env_var) {
        mode = PasswordMode::FromEnvironment;
    }

    try {
        if (cmd == "encrypt") {
            ProgressTracker tracker;
            EncryptCliArgs eargs;
            eargs.files         = pa.files;
            eargs.password_mode = mode;
            eargs.password_file = pa.password_file;
            eargs.no_safe       = pa.no_safe;
            eargs.jobs          = pa.jobs;
            eargs.jobs_explicit = pa.jobs_explicit;
            eargs.output_dir    = pa.output_dir;
            eargs.chunk_size    = pa.chunk_size;
            eargs.chunk_size_explicit = pa.chunk_size_explicit;
            eargs.verbose       = pa.verbose;
            eargs.quiet         = pa.quiet;
            eargs.compression       = pa.compression;
            eargs.compression_level = pa.compression_level;
            eargs.auto_mode     = pa.auto_mode;
            eargs.auto_dir      = pa.auto_dir;
            eargs.max_depth     = pa.max_depth;
            return static_cast<int>(run_encrypt(eargs, tracker));
        }
        if (cmd == "decrypt") {
            ProgressTracker tracker;
            DecryptCliArgs dargs;
            dargs.files         = pa.files;
            dargs.password_mode = mode;
            dargs.password_file = pa.password_file;
            dargs.no_safe       = pa.no_safe;
            dargs.jobs          = pa.jobs;
            dargs.jobs_explicit = pa.jobs_explicit;
            dargs.output_dir    = pa.output_dir;
            dargs.chunk_size    = pa.chunk_size;
            dargs.chunk_size_explicit = pa.chunk_size_explicit;
            dargs.verbose       = pa.verbose;
            dargs.quiet         = pa.quiet;
            dargs.auto_mode     = pa.auto_mode;
            dargs.auto_dir      = pa.auto_dir;
            dargs.max_depth     = pa.max_depth;
            return static_cast<int>(run_decrypt(dargs, tracker));
        }
        return static_cast<int>(run_list(pa.files));
    } catch (const LockError& e) {
        emit_error(e.what());
        return static_cast<int>(e.code());
    } catch (const std::exception& e) {
        emit_error(e.what());
        return static_cast<int>(classify_runtime_error(e.what()));
    }
}

}  // namespace lock

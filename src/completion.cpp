// lock::completion — runtime shell-completion-script generator.  See
// include/lock/completion.hpp for the public surface.
#include <lock/completion.hpp>

#include <ostream>
#include <string>
#include <string_view>

namespace lock {

namespace {

// ---------------------------------------------------------------------------
// Script emitters.  Each shell's surface (subcommands + per-subcommand
// flags + enum values) is hardcoded as a literal shell string — this is
// the safest representation because shell syntax errors compound across
// multiline C++ literals, and the maintainer reading the file must be able
// to see the exact shell that will be sourced.  The grammar below mirrors
// src/cli.cpp's parse_args; cli.cpp's localized wording is intentionally
// NOT consulted because that wording is user-facing, and a drift here is
// caught by smoke.sh at the end of Wave B before any release.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Bash — defines `_lock()` and registers the completion function for both
// `lock` and its three subcommand synonyms (so `lock encrypt -<TAB>` works
// even if the user invokes the binary under a different `lock-<cmd>` name).
// `complete -o default -F _lock ...` keeps bash's default file/dir listing
// for positional args AND for "file"/"dir"-typed flag values.
// ---------------------------------------------------------------------------
void emit_bash(std::ostream& out) {
    out <<
        "# lock --completion bash  (generated at runtime by `lock` itself)\n"
        "# Usage: eval \"$(lock --completion bash)\"\n"
        "# Or install to ${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/lock\n"
        "\n"
        "_lock() {\n"
        "    local cur prev words cword\n"
        "    _init_completion 2>/dev/null || {\n"
        "        cur=\"${COMP_WORDS[COMP_CWORD]}\"\n"
        "        prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n"
        "        words=(\"${COMP_WORDS[@]}\")\n"
        "        cword=$COMP_CWORD\n"
        "    }\n"
        "\n"
        "    # Subcommand detection: first non-flag arg after `lock` itself.\n"
        "    local sub=\"\"\n"
        "    local i\n"
        "    for ((i=1; i<${#words[@]}; i++)); do\n"
        "        if [[ \"${words[i]}\" == -* ]]; then\n"
        "            # Skip the value of any value-taking flag.\n"
        "            case \"${words[i]}\" in\n"
        "                -p|--password-file|-j|--jobs|-o|--output-dir|"
        "--chunk-size|--compress|--level|--auto|--max-depth|--lang)\n"
        "                    ((i++)) ;;\n"
        "                --password-file=*|--jobs=*|--output-dir=*|"
        "--chunk-size=*|--compress=*|--level=*|--auto=*|--max-depth=*|"
        "--lang=*) ;;\n"
        "            esac\n"
        "            continue\n"
        "        fi\n"
        "        [[ $i -eq 1 || \"${words[i-1]}\" != -* || "
        "\"${words[i-1]}\" == -- ]] && { sub=\"${words[i]}\"; break; }\n"
        "    done\n"
        "\n"
        "    # Common flags visible to every subcommand.\n"
        "    local common_flags=(\n"
        "        -p --password-file\n"
        "        -pev --password-env-var\n"
        "        --no-safe\n"
        "        -j --jobs\n"
        "        -o --output-dir\n"
        "        --chunk-size\n"
        "        -v --verbose\n"
        "        -q --quiet\n"
        "        --lang\n"
        "        --no-color\n"
        "        --version\n"
        "        -h --help\n"
        "    )\n"
        "    local encrypt_flags=(\n"
        "        --compress -z --fast --level --auto --max-depth\n"
        "    )\n"
        "\n"
        "    # If no subcommand has been typed yet, complete subcommand names.\n"
        "    if [[ -z \"$sub\" ]]; then\n"
        "        COMPREPLY=( $(compgen -W \"encrypt decrypt list\" -- \"$cur\") )\n"
        "        return 0\n"
        "    fi\n"
        "\n"
        "    # Value completion for the flag immediately before the cursor.\n"
        "    case \"$prev\" in\n"
        "        --compress)\n"
        "            COMPREPLY=( $(compgen -W \"none lz4 zstd\" -- \"$cur\") ); return 0 ;;\n"
        "        --lang)\n"
        "            COMPREPLY=( $(compgen -W \"en zh\" -- \"$cur\") ); return 0 ;;\n"
        "        --level|--max-depth|-j|--jobs|--chunk-size)\n"
        "            COMPREPLY=( $(compgen -P '' -- \"$cur\" <<< '') ); return 0 ;;\n"
        "        -p|--password-file)\n"
        "            COMPREPLY=( $(compgen -f -- \"$cur\") ); return 0 ;;\n"
        "        -o|--output-dir|--auto)\n"
        "            COMPREPLY=( $(compgen -d -- \"$cur\") ); return 0 ;;\n"
        "    esac\n"
        "\n"
        "    # `--flag=value` style: complete the value half inline.\n"
        "    if [[ \"$cur\" == --*=* ]]; then\n"
        "        local flagbody=\"${cur%%=*}\"\n"
        "        local val=\"${cur#*=}\"\n"
        "        case \"$flagbody\" in\n"
        "            --compress) COMPREPLY=( $(compgen -W \"none lz4 zstd\" -- \"$val\") ) ;;\n"
        "            --lang)     COMPREPLY=( $(compgen -W \"en zh\" -- \"$val\") ) ;;\n"
        "            --password-file|-p)    COMPREPLY=( $(compgen -f -- \"$val\") ) ;;\n"
        "            --output-dir|--auto)   COMPREPLY=( $(compgen -d -- \"$val\") ) ;;\n"
        "            *) COMPREPLY=() ;;\n"
        "        esac\n"
        "        return 0\n"
        "    fi\n"
        "\n"
        "    # Flag-name completion after `-`.\n"
        "    if [[ \"$cur\" == -* ]]; then\n"
        "        local flags=(\"${common_flags[@]}\")\n"
        "        case \"$sub\" in\n"
        "            encrypt) flags+=( \"${encrypt_flags[@]}\" ) ;;\n"
        "            decrypt|list) ;;   # no encrypt-only flags after these\n"
        "        esac\n"
        "        COMPREPLY=( $(compgen -W \"${flags[*]}\" -- \"$cur\") )\n"
        "        return 0\n"
        "    fi\n"
        "\n"
        "    # Fall back to bash's default (file) completion for positionals.\n"
        "    _filedir 2>/dev/null || _filedir_xspec 2>/dev/null\n"
        "    return 0\n"
        "}\n"
        "\n"
        "# Register against `lock` and the three subcommand synonyms so that\n"
        "# both `lock encrypt -<TAB>` and `encrypt -<TAB>` (in PATH/alias flows)\n"
        "# route through the same `_lock` completion function.\n"
        "complete -o default -o filenames -F _lock lock encrypt decrypt list\n"
        "\n"
        "# End of `lock --completion bash`\n";
}

// ---------------------------------------------------------------------------
// Zsh — `#compdef lock` + `_arguments` per subcommand route.  After
// `autoload compinit && compinit`, `eval "$(lock --completion zsh)"` makes
// `lock`, `lock encrypt`, `lock decrypt`, `lock list` all complete the same
// surface as bash.  Uses `_pick_variant` to switch on the subcommand.
// ---------------------------------------------------------------------------
void emit_zsh(std::ostream& out) {
    out <<
        "#compdef lock\n"
        "# lock --completion zsh  (generated at runtime by `lock` itself)\n"
        "# Usage: eval \"$(lock --completion zsh)\"\n"
        "# Or copy to a directory on $fpath as `_lock`.\n"
        "\n"
        "_lock() {\n"
        "    local -a common_args\n"
        "    common_args=(\n"
        "        '-p+[password file]:file:_files'\n"
        "        '--password-file+[password file]:file:_files'\n"
        "        '--password-env-var'\n"
        "        '-pev'\n"
        "        '--no-safe'\n"
        "        '-j+[worker threads]:N: '\n"
        "        '--jobs+[worker threads]:N: '\n"
        "        '-o+[output directory]:dir:_dirs'\n"
        "        '--output-dir+[output directory]:dir:_dirs'\n"
        "        '--chunk-size+[bytes]:bytes: '\n"
        "        '-v[verbose]'\n"
        "        '--verbose[verbose]'\n"
        "        '-q[quiet]'\n"
        "        '--quiet[quiet]'\n"
        "        '--lang+[UI language]:lang:(en zh)'\n"
        "        '--no-color'\n"
        "        '--version'\n"
        "        '-h[help]'\n"
        "        '--help[help]'\n"
        "        '*:file:_files'\n"
        "    )\n"
        "\n"
        "    local -a encrypt_args\n"
        "    encrypt_args=(\n"
        "        '--compress+[compression algorithm]:algo:(none lz4 zstd)'\n"
        "        '-z[compress with zstd]'\n"
        "        '--fast[compress with lz4]'\n"
        "        '--level+[compression level]:N: '\n"
        "        '--auto+[batch mode directory]:dir:_dirs'\n"
        "        '--max-depth+[recursion depth]:N: '\n"
        "    )\n"
        "\n"
        "    _arguments -C $common_args \\\n"
        "        'encrypt:dummy:->encrypt' \\\n"
        "        'decrypt:dummy:->decrypt' \\\n"
        "        'list:dummy:->list'\n"
        "\n"
        "    case $state in\n"
        "        encrypt)\n"
        "            _arguments $common_args $encrypt_args '*:file:_files' ;;\n"
        "        decrypt)\n"
        "            _arguments $common_args '*:file:_files' ;;\n"
        "        list)\n"
        "            _arguments $common_args '*:file:_files' ;;\n"
        "    esac\n"
        "}\n"
        "\n"
        "_lock \"$@\"\n"
        "\n"
        "# End of `lock --completion zsh`\n";
}

// ---------------------------------------------------------------------------
// Fish — `complete -c lock ...` statements.  fish's model is declarative;
// we register one `complete -c lock -a ...` line per flag, with `-r` for
// value-taking flags and `-f` to suppress file completion only inside the
// flag-name position.  `-n` guards restrict each rule to the active
// subcommand line.
// ---------------------------------------------------------------------------
void emit_fish(std::ostream& out) {
    out <<
        "# lock --completion fish  (generated at runtime by `lock` itself)\n"
        "# Usage: lock --completion fish | source\n"
        "\n"
        "# Subcommand list as the first positional after `lock`.\n"
        "complete -c lock -n '__fish_use_subcommand' -a 'encrypt' -d 'Encrypt files'\n"
        "complete -c lock -n '__fish_use_subcommand' -a 'decrypt' -d 'Decrypt files'\n"
        "complete -c lock -n '__fish_use_subcommand' -a 'list'    -d 'Print metadata'\n"
        "\n"
        "# ---- Common flags (every subcommand) ----\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt decrypt list' "
        "-s p -l password-file -r -F\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt decrypt list' "
        "-l password-env-var\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt decrypt list' "
        "-l no-safe\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt decrypt list' "
        "-s j -l jobs -r\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt decrypt list' "
        "-s o -l output-dir -r\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt decrypt list' "
        "-l chunk-size -r\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt decrypt list' "
        "-s v -l verbose\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt decrypt list' "
        "-s q -l quiet\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt decrypt list' "
        "-l lang -r -f -a 'en zh'\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt decrypt list' "
        "-l no-color\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt decrypt list' "
        "-l version\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt decrypt list' "
        "-s h -l help\n"
        "\n"
        "# ---- Encrypt-only ----\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt' "
        "-l compress -r -f -a 'none lz4 zstd'\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt' "
        "-s z\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt' "
        "-l fast\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt' "
        "-l level -r\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt' "
        "-l auto -r\n"
        "complete -c lock -n '__fish_seen_subcommand_from encrypt' "
        "-l max-depth -r\n"
        "\n"
        "# End of `lock --completion fish`\n";
}

}  // namespace (anonymous)

// ---------------------------------------------------------------------------
// Public API (see completion.hpp header).
// ---------------------------------------------------------------------------

bool is_supported_shell(std::string_view name) noexcept {
    return name == "bash" || name == "zsh" || name == "fish";
}

bool parse_completion_shell(std::string_view name,
                            CompletionShell& out) noexcept {
    if (name == "bash") { out = CompletionShell::Bash; return true; }
    if (name == "zsh")  { out = CompletionShell::Zsh;  return true; }
    if (name == "fish") { out = CompletionShell::Fish; return true; }
    return false;
}

std::string_view supported_shells_label() noexcept {
    return "bash, zsh, fish";
}

void print_completion(CompletionShell shell, std::ostream& out) {
    switch (shell) {
        case CompletionShell::Bash: emit_bash(out); return;
        case CompletionShell::Zsh:  emit_zsh(out);  return;
        case CompletionShell::Fish: emit_fish(out); return;
    }
}

bool print_completion_for(std::string_view shell_name, std::ostream& out) {
    CompletionShell cs;
    if (!parse_completion_shell(shell_name, cs)) {
        return false;
    }
    print_completion(cs, out);
    return true;
}

}  // namespace lock

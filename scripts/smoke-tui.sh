#!/usr/bin/env bash
# Wave C smoke test for lock TUI (--tui).
# Tests:
#   1. Non-tty → exit 2 + guard message
#   2. --no-color + pty → exit 2 + colour-guard message
#   3. Main menu renders all 4 items (Chinese locale)
#   4. Encrypt form renders all fields (Chinese locale)
#   5. Decrypt form renders all fields (Chinese locale)
#   6. List placeholder renders (Chinese locale)
#   7. Wizard flow: navigate to Quit → Enter → exit 0
#   8. CLI round-trip encrypt/decrypt via password file (regression)
#
# Dependencies: script(1) for pty creation, sed for ANSI stripping.
# Usage: set LOCK=<path> to override the binary path (default: ./build/lock).
set -euo pipefail

LOCK="${LOCK:-./build/lock}"
[ -x "$LOCK" ] || { echo "FATAL: $LOCK not found or not executable"; exit 1; }

PASS=0
FAIL=0
TOTAL=0

report() {
    local name="$1" ok="$2"
    TOTAL=$((TOTAL+1))
    if [ "$ok" -eq 0 ]; then
        PASS=$((PASS+1))
        echo "PASS: $name"
    else
        FAIL=$((FAIL+1))
        echo "FAIL: $name"
    fi
}

# Run the TUI under a pty, capture output to a temp file, then strip ANSI
# and null bytes to plain text.  Returns the temp file path for grep(1) to
# read directly — avoids bash $(...) command substitution which silently
# strips null bytes and can corrupt Unicode text.
capture_tui() {
    local raw
    raw=$(mktemp /tmp/lock_tui_raw_XXXXXX)
    local lang="${1:-zh}" timeout_sec="${2:-2}" keystrokes="${3:-}"
    if [ -n "$keystrokes" ]; then
        timeout "$timeout_sec" script -qec "$LOCK --lang $lang --tui" /dev/null \
            < <(printf '%s' "$keystrokes") > "$raw" 2>/dev/null || true
    else
        timeout "$timeout_sec" script -qec "$LOCK --lang $lang --tui" /dev/null \
            > "$raw" 2>/dev/null || true
    fi
    local clean
    clean=$(mktemp /tmp/lock_tui_clean_XXXXXX)
    sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$raw" | tr -d '\0' > "$clean"
    rm -f "$raw"
    echo "$clean"
}

# ---------- 1. Non-tty → exit 2 ----------
echo "--- Test 1: non-tty guard ---"
rc=0
err_output=$( "$LOCK" --lang zh --tui 2>&1 ) || rc=$?
if [ $rc -eq 2 ]; then
    echo "$err_output" | grep -qiE "(TUI 模式需要交互式终端|TUI mode requires.*tty)" \
        && report "non-tty: exit code 2 + guard message" 0 \
        || report "non-tty: missing guard message in stderr" 1
else
    report "non-tty: expected rc=2, got rc=$rc" 1
fi

# ---------- 2. --no-color + pty → exit 2 ----------
echo "--- Test 2: --no-color guard ---"
rc=0
err_output=$( script -qec "$LOCK --lang zh --tui --no-color" /dev/null 2>&1 ) || rc=$?
if [ $rc -eq 2 ]; then
    echo "$err_output" | grep -qiE "(TUI 模式需要彩色支持|TUI mode requires colour)" \
        && report "--no-color: exit code 2 + colour-guard message" 0 \
        || report "--no-color: missing colour-guard message in stderr" 1
else
    report "--no-color: expected rc=2, got rc=$rc" 1
fi

# ---------- 3. Main menu items ----------
echo "--- Test 3: main menu items ---"
clean_f=$( capture_tui zh 2 )
ok=0
grep -q "加密 (Encrypt)" "$clean_f"  || { ok=1; echo "  missing: 加密 (Encrypt)"; }
grep -q "解密 (Decrypt)" "$clean_f"  || { ok=1; echo "  missing: 解密 (Decrypt)"; }
grep -q "查看 (List)"     "$clean_f" || { ok=1; echo "  missing: 查看 (List)"; }
grep -q "退出 (Quit)"     "$clean_f" || { ok=1; echo "  missing: 退出 (Quit)"; }
rm -f "$clean_f"
report "main menu: 4 items present" "$ok"

# ---------- 4. Encrypt form fields ----------
echo "--- Test 4: encrypt form fields ---"
clean_f=$( capture_tui zh 3 $'\r' )
ok=0
grep -q "加密"              "$clean_f" || { ok=1; echo "  missing: encrypt form title"; }
grep -q "文件"              "$clean_f" || { ok=1; echo "  missing: files field"; }
grep -q "压缩算法"          "$clean_f" || { ok=1; echo "  missing: compression section"; }
grep -q "不压缩"            "$clean_f" || { ok=1; echo "  missing: compress none"; }
grep -q "lz4 (快)"          "$clean_f" || { ok=1; echo "  missing: lz4"; }
grep -q "zstd (均衡)"       "$clean_f" || { ok=1; echo "  missing: zstd"; }
grep -q "压缩级别"          "$clean_f" || { ok=1; echo "  missing: level field"; }
grep -q "并发数"            "$clean_f" || { ok=1; echo "  missing: jobs field"; }
grep -q "输出目录"          "$clean_f" || { ok=1; echo "  missing: output dir field"; }
grep -q "密码 (输入不可见)" "$clean_f" || { ok=1; echo "  missing: password field"; }
grep -q "确认密码"          "$clean_f" || { ok=1; echo "  missing: confirm password field"; }
grep -q "确认"              "$clean_f" || { ok=1; echo "  missing: confirm button"; }
grep -q "取消"              "$clean_f" || { ok=1; echo "  missing: cancel button"; }
rm -f "$clean_f"
report "encrypt form: all fields present" "$ok"

# ---------- 5. Decrypt form fields ----------
echo "--- Test 5: decrypt form fields ---"
clean_f=$( capture_tui zh 3 $'\x1b[B\r' )
ok=0
grep -q "解密"              "$clean_f" || { ok=1; echo "  missing: decrypt form title"; }
grep -q "文件"              "$clean_f" || { ok=1; echo "  missing: files field"; }
grep -q "并发数"            "$clean_f" || { ok=1; echo "  missing: jobs field"; }
grep -q "输出目录"          "$clean_f" || { ok=1; echo "  missing: output dir field"; }
grep -q "密码 (输入不可见)" "$clean_f" || { ok=1; echo "  missing: password field"; }
grep -q "确认"              "$clean_f" || { ok=1; echo "  missing: confirm button"; }
grep -q "取消"              "$clean_f" || { ok=1; echo "  missing: cancel button"; }
rm -f "$clean_f"
report "decrypt form: all fields present" "$ok"

# ---------- 6. List placeholder ----------
echo "--- Test 6: list placeholder ---"
clean_f=$( capture_tui zh 3 $'\x1b[B\x1b[B\r' )
ok=0
grep -qi "TUI 模式不可用\|List.*not available" "$clean_f" \
    && report "list placeholder: message present" 0 \
    || report "list placeholder: missing not-available message" 1
rm -f "$clean_f"

# ---------- 7. Wizard flow: navigate to Quit → Enter → exit 0 ----------
echo "--- Test 7: wizard exit flow ---"
rc=0
# 3× Down arrow (to Quit) + Enter (select Quit) → screen.Exit → ExitCode::Ok
printf '\x1b[B\x1b[B\x1b[B\r' | script -qec "$LOCK --lang zh --tui" /dev/null 2>/dev/null || rc=$?
if [ $rc -eq 0 ]; then
    report "wizard flow: navigate to Quit → exit 0" 0
else
    report "wizard flow: expected rc=0, got rc=$rc" 1
fi

# ---------- 8. CLI round-trip (regression) ----------
echo "--- Test 8: CLI encrypt/decrypt round-trip ---"
WORKDIR=$(mktemp -d /tmp/lock_wavec_XXXXXX)
trap 'rm -rf "$WORKDIR"' EXIT

echo "Hello lock Wave C round-trip test. 日本語もOK。" > "$WORKDIR/plain.txt"
echo -n 'waveC-password-123' > "$WORKDIR/pw.txt"

"$LOCK" encrypt "$WORKDIR/plain.txt" \
    -o "$WORKDIR/out/" \
    -j 1 \
    -p "$WORKDIR/pw.txt" --no-safe \
    2>/dev/null \
    || { report "encrypt round-trip: command failed" 1; false; }

[ -f "$WORKDIR/out/plain.txt.locked" ] \
    || { report "encrypt round-trip: .locked not created" 1; false; }

"$LOCK" decrypt "$WORKDIR/out/plain.txt.locked" \
    -o "$WORKDIR/dec/" \
    -j 1 \
    -p "$WORKDIR/pw.txt" --no-safe \
    2>/dev/null \
    || { report "decrypt round-trip: command failed" 1; false; }

diff "$WORKDIR/plain.txt" "$WORKDIR/dec/plain.txt" \
    && report "CLI round-trip: content matches after decrypt" 0 \
    || report "CLI round-trip: content mismatch" 1

# ---------- Summary ----------
echo ""
echo "===================="
echo " Smoke Test Summary "
echo "===================="
echo " Total: $TOTAL"
echo " PASS:  $PASS"
echo " FAIL:  $FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo " ==> ALL PASS"
else
    echo " ==> SOME TESTS FAILED"
    exit 1
fi

#!/usr/bin/env bash
#
# libedhoc Linux CI helper: a thin wrapper around the CMake presets. Every step
# is one `scripts/ci.sh <cmd>`, reproducible locally. (Zephyr uses west/twister.)
#
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_DIR}"

# Functional matrix: one entry per ephemeral family x memory backend. Each family
# covers its suite(s): x25519 = suites 0 & 4, p256 = 2, p384 = 24, mlkem512 =
# pqc_1. Single source of truth for `matrix` and `check-matrix`.
MATRIX_PRESETS=(
    x25519_stack   x25519_heap   x25519_custom
    p256_stack     p256_heap     p256_custom
    p384_stack     p384_heap     p384_custom
    mlkem512_stack mlkem512_heap mlkem512_custom
    p256_limits
)

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'
section() { echo -e "\n${BLUE}=== $* ===${NC}"; }
ok()      { echo -e "${GREEN}$*${NC}"; }
err()     { echo -e "${RED}$*${NC}" >&2; }
require() { command -v "$1" >/dev/null 2>&1 || { err "Error: '$1' is not installed"; exit 1; }; }

# ctest wrapper: fail if a preset unexpectedly has zero tests, and disable ASLR
# for the sanitizer preset (ASan cannot initialise under high mmap_rnd_bits).
run_ctest() {
    local preset="$1"; shift || true
    local wrap=()
    if [[ "$preset" == "asan" ]] && command -v setarch >/dev/null 2>&1; then
        wrap=(setarch -R)
    fi
    CTEST_NO_TESTS_ACTION=error "${wrap[@]}" ctest --preset "$preset" --output-on-failure "$@"
}

# --- build / test / ci (per preset) ------------------------------------------
cmd_build() {
    section "build ${1}${2:+ (target ${2})}"
    cmake --preset "$1" >/dev/null
    cmake --build --preset "$1" -j"$(nproc)" ${2:+--target "$2"}
    ok "built ${1}"
}

cmd_test() {
    section "test ${1}"
    run_ctest "$1"
}

cmd_ci() {
    cmd_build "$1"
    cmd_test "$1"
    ok "ci ${1} passed"
}

# --- matrix: build + test every functional preset ----------------------------
cmd_matrix() {
    for p in "${MATRIX_PRESETS[@]}" legacy; do
        cmd_build "$p"
        cmd_test "$p"
    done
    ok "\nFull matrix passed (${#MATRIX_PRESETS[@]} preset(s) + legacy)."
}

# --- check-matrix ------------------------------------------------------------
# Fail if any test_*.c under tests/linux is built by no preset (it would
# silently never run). Bundled tiers (unit/, robustness/) compile many files
# into one binary, so they are excluded here.
cmd_check_matrix() {
    section "check-matrix: every test file runs in >= 1 preset"
    local union
    union="$(
        for p in "${MATRIX_PRESETS[@]}" legacy; do
            cmake --preset "$p" >/dev/null 2>&1 || { err "configure failed: $p"; exit 1; }
            ctest --preset "$p" -N 2>/dev/null | sed -n 's/.*Test #[0-9]*: //p'
        done | sort -u
    )"

    local missing=0 f t count=0
    while IFS= read -r f; do
        count=$((count + 1))
        t="$(basename "$f" .c)"
        grep -qxF "$t" <<<"$union" \
            || { err "  '$t' is built by NO preset — it would silently never run"; missing=1; }
    done < <(find tests/linux -name 'test_*.c' -not -path '*/support/*' -not -path '*/unit/*' -not -path '*/robustness/*' | sort -u)

    if [[ $missing -ne 0 ]]; then
        err "check-matrix FAILED: orphaned test file(s) above."
        exit 1
    fi
    ok "check-matrix passed: ${count} test file(s) each run in >= 1 preset."
}

# --- coverage (gcovr) --------------------------------------------------------
cmd_coverage() {
    require gcovr
    cmd_build coverage
    cmd_test coverage
    section "coverage report (gcovr)"
    mkdir -p build/coverage/report
    gcovr --root "${PROJECT_DIR}" \
          --exclude '.*/externals/.*' \
          --exclude '.*/tests/.*' \
          --exclude '.*/backends/cbor/src/.*' \
          --print-summary \
          --cobertura build/coverage/report/coverage.xml --cobertura-pretty \
          --html-details build/coverage/report/index.html \
          build/coverage
    ok "HTML report:      build/coverage/report/index.html"
    ok "Cobertura report: build/coverage/report/coverage.xml"
}

# --- sanitizers (ASan + UBSan) ----------------------------------------------
cmd_sanitizers() { cmd_build asan; cmd_test asan; }

# --- valgrind (memcheck + DRD over a preset's binaries) ----------------------
cmd_valgrind() {
    require valgrind
    # The valgrind preset builds all suites with portable liboqs; pass another
    # preset for a lighter run.
    local preset="${1:-valgrind}"
    section "valgrind memcheck + DRD (${preset})"
    cmake --preset "$preset" >/dev/null
    cmake --build --preset "$preset" -j"$(nproc)"

    local found=0 bin
    while IFS= read -r bin; do
        found=1
        echo "--- memcheck $(basename "$bin") ---"
        valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
                 --error-exitcode=1 -s "$bin"
    done < <(find "build/${preset}/tests" -type f -perm -u+x -name 'test_*' ! -name '*.o')
    [[ $found -eq 1 ]] || { err "No test binaries found under build/${preset}/tests"; exit 1; }
    ok "valgrind passed (${preset})."
}

# --- fuzz --------------------------------------------------------------------
cmd_fuzz() {
    local duration="${1:-60}"
    section "fuzz (${duration}s per target)"
    cmd_build fuzz
    local artifacts="build/fuzz/artifacts"
    rm -rf "$artifacts"
    mkdir -p "$artifacts"
    local found=0 failed=() target status
    for target in build/fuzz/tests/linux/fuzz/fuzz_*; do
        [[ -x "$target" && ! "$target" == *.o ]] || continue
        found=1
        echo "--- $(basename "$target") ---"
        status=0
        timeout "$duration" "$target" -max_total_time="$duration" \
            -artifact_prefix="${artifacts}/" || status=$?
        [[ $status -eq 0 || $status -eq 124 ]] ||
            failed+=("$(basename "$target") (exit ${status})")
    done
    [[ $found -eq 1 ]] || { err "No fuzz targets in build/fuzz/tests/linux/fuzz/"; exit 1; }
    if [[ ${#failed[@]} -ne 0 ]]; then
        err "fuzz failed: ${failed[*]}"
        err "reproducers in ${artifacts}/"
        exit 1
    fi
    ok "fuzz complete."
}

# --- format ------------------------------------------------------------------
cmd_format() {
    require clang-format; require git
    local check=false
    [[ "${1:-}" == "--check" ]] && check=true
    local files=()
    mapfile -t files < <(git ls-files '*.c' '*.h' ':!:backends/**')
    [[ ${#files[@]} -gt 0 ]] || { err "No source files found."; exit 1; }
    if [[ "$check" == true ]]; then
        section "format --check"
        clang-format --dry-run --Werror --style=file "${files[@]}"
        ok "formatting OK."
    else
        section "format"
        clang-format -i --style=file "${files[@]}"
        ok "formatted ${#files[@]} file(s)."
    fi
}

# --- cppcheck ----------------------------------------------------------------
cmd_cppcheck() {
    require cppcheck
    section "cppcheck"
    cppcheck --enable=warning,style --inline-suppr --error-exitcode=1 \
        -I include/ -I library/internal/ -I backends/cbor/include/ \
        library/core/*.c
    ok "cppcheck passed."
}

# --- clang-tidy --------------------------------------------------------------
cmd_clang_tidy() {
    require clang-tidy
    section "clang-tidy"
    # Build XKCP's generated headers first, else clang-tidy aborts on the
    # KMAC256 KDF source.
    cmake --preset legacy -B build/tidy -DCMAKE_C_COMPILER=clang >/dev/null
    cmake --build build/tidy --target xkcp_build >/dev/null
    clang-tidy -p build/tidy \
        library/core/*.c \
        library/cipher_suites/*.c \
        library/cipher_suites/*/*.c
    ok "clang-tidy passed."
}

# --- check-headers -----------------------------------------------------------
# Installed public headers must never include a private *_internal.h header.
cmd_check_headers() {
    section "public header hygiene"
    local offenders
    offenders=$(grep -rEn '#[[:space:]]*include[[:space:]]*[<"][^">]*_internal\.h[">]' include/ || true)
    [[ -z "$offenders" ]] || { err "Public headers must not include *_internal.h:"; err "$offenders"; exit 1; }
    ok "no public header includes a private *_internal.h header."
}

cmd_list() { cmake --list-presets; }

show_help() {
    cat <<'EOF'
Usage: scripts/ci.sh <command> [args]

Per-preset (see `scripts/ci.sh list`):
  build <preset>        cmake --preset <p> && cmake --build --preset <p>
  test  <preset>        ctest --preset <p>   (CTEST_NO_TESTS_ACTION=error)
  ci    <preset>        build + test

Matrix:
  matrix                build + test every functional preset + legacy
  check-matrix          fail if any test_*.c is built by no preset (anti-skip net)

Instrumentation:
  coverage              coverage preset + gcovr HTML report
  sanitizers            asan preset (ASan/UBSan; ASLR auto-disabled locally)
  valgrind [preset]     memcheck + DRD over a preset's binaries
                        (default: valgrind preset = all suites incl. PQC)
  fuzz [seconds]        build + run libFuzzer targets (default: 60s each)

Quality:
  format [--check]      clang-format all tracked sources
  cppcheck              static analysis (library core)
  clang-tidy            static analysis (library, clang compile db)
  check-headers         public headers must not include *_internal.h

  list                  list all CMake presets
  help                  this message

Examples:
  scripts/ci.sh ci p256_stack           # one preset, end to end
  scripts/ci.sh matrix                  # the whole functional matrix
  scripts/ci.sh coverage                # gcov + gcovr report
  scripts/ci.sh valgrind p256_stack     # memcheck a lighter (classic) preset
EOF
}

main() {
    [[ $# -eq 0 ]] && { show_help; exit 0; }
    local cmd="$1"; shift || true
    case "$cmd" in
        build)         cmd_build "${1:?preset required}" "${2:-}" ;;
        test)          cmd_test "${1:?preset required}" ;;
        ci)            cmd_ci "${1:?preset required}" ;;
        matrix)        cmd_matrix ;;
        check-matrix)  cmd_check_matrix ;;
        coverage)      cmd_coverage ;;
        sanitizers)    cmd_sanitizers ;;
        valgrind)      cmd_valgrind "$@" ;;
        fuzz)          cmd_fuzz "${1:-60}" ;;
        format)        cmd_format "${1:-}" ;;
        cppcheck)      cmd_cppcheck ;;
        clang-tidy)    cmd_clang_tidy ;;
        check-headers) cmd_check_headers ;;
        list)          cmd_list ;;
        help|--help|-h) show_help ;;
        *)             err "Unknown command: $cmd"; show_help; exit 1 ;;
    esac
}

main "$@"

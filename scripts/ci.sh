#!/bin/bash
set -euo pipefail

# -----------------------------------------------------------------------------
# libedhoc unified CI script
# Single entry point for all build, test, analysis, and benchmark tasks.
# Every CI job calls this script — nothing should be duplicated in YAML.
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"

# --------------- Shared CMake configuration (single source of truth) ---------
KCONFIG_OPTIONS=(
    -DCONFIG_LIBEDHOC_ENABLE=1
    -DCONFIG_LIBEDHOC_KEY_ID_LEN=4
    -DCONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES=3
    -DCONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID=7
    -DCONFIG_LIBEDHOC_MAX_LEN_OF_KEM_PUBLIC_KEY=48
    -DCONFIG_LIBEDHOC_MAX_LEN_OF_KEM_CIPHERTEXT=48
    -DCONFIG_LIBEDHOC_MAX_LEN_OF_NIKE_KEY=48
    -DCONFIG_LIBEDHOC_MAX_LEN_OF_MAC=48
    -DCONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS=3
    -DCONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID=1
    -DCONFIG_LIBEDHOC_MAX_LEN_OF_HASH_ALG=1
    -DCONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN=2
    -DCONFIG_LIBEDHOC_LOG_LEVEL=4
)

MBEDTLS_OPTIONS=(
    -DENABLE_PROGRAMS=OFF
    -DENABLE_TESTING=OFF
)

# --------------- Terminal colours --------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

section() { echo -e "\n${BLUE}=== $* ===${NC}\n"; }
ok()      { echo -e "${GREEN}$*${NC}"; }
err()     { echo -e "${RED}$*${NC}" >&2; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { err "Error: $1 is not installed"; exit 1; }
}

# --------------- Helpers -----------------------------------------------------
cmake_configure() {
    local extra_args=("$@")
    rm -rf "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"
    cmake -B "${BUILD_DIR}" -S "${PROJECT_DIR}" \
        "${KCONFIG_OPTIONS[@]}" \
        "${MBEDTLS_OPTIONS[@]}" \
        -DCMAKE_BUILD_TYPE=Debug \
        "${extra_args[@]}"
}

cmake_build() {
    cmake --build "${BUILD_DIR}" -j"$(nproc)"
}

test_binary() {
    echo "${BUILD_DIR}/tests/libedhoc_module_tests"
}

# ============================================================================
# Subcommands
# ============================================================================

# --------------- build -------------------------------------------------------
cmd_build() {
    local compiler="gcc"
    local coverage=false sanitizers=false fuzz=false
    local mem_backend=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --gcc)        compiler="gcc" ;;
            --clang)      compiler="clang" ;;
            --coverage)   coverage=true ;;
            --sanitizers) sanitizers=true ;;
            --fuzz)       fuzz=true ;;
            --mem-backend) shift; mem_backend="${1:-}" ;;
            *) err "Unknown build option: $1"; exit 1 ;;
        esac
        shift
    done

    section "Build (${compiler}${mem_backend:+, mem=${mem_backend}})"

    local experimental_pqc=ON
    [[ "$coverage" == true ]] && experimental_pqc=OFF

    local cmake_args=(-DLIBEDHOC_ENABLE_TESTS=ON
                      -DLIBEDHOC_ENABLE_EXPERIMENTAL_PQC="${experimental_pqc}")

    if [[ "$compiler" == "gcc" ]]; then
        cmake_args+=(-DCMAKE_C_COMPILER=gcc)
    else
        cmake_args+=(-DCMAKE_C_COMPILER=clang
                      -G Ninja)
    fi

    [[ "$coverage" == true ]]   && cmake_args+=(-DLIBEDHOC_ENABLE_COVERAGE=ON)
    [[ "$sanitizers" == true ]] && cmake_args+=(-DLIBEDHOC_ENABLE_SANITIZERS=ON)

    if [[ -n "$mem_backend" ]]; then
        # Translate the friendly name to the integer CONFIG_LIBEDHOC_MEM_BACKEND:
        # 0 stack, 1 heap, 2 custom.
        local mem_backend_value
        case "$mem_backend" in
            stack)  mem_backend_value=0 ;;
            heap)   mem_backend_value=1 ;;
            custom) mem_backend_value=2 ;;
            *) err "Unknown memory backend: ${mem_backend} (use stack|heap|custom)"; exit 1 ;;
        esac
        cmake_args+=(-DCONFIG_LIBEDHOC_MEM_BACKEND="${mem_backend_value}")
    fi

    if [[ "$fuzz" == true ]]; then
        cmake_args=(-DCMAKE_C_COMPILER=clang
                     -DLIBEDHOC_ENABLE_FUZZING=ON -G Ninja)
    fi

    cmake_configure "${cmake_args[@]}"
    cmake_build
    ok "Build complete: ${BUILD_DIR}"
}

# --------------- test --------------------------------------------------------
cmd_test() {
    section "Running tests"
    local bin
    bin="$(test_binary)"
    [[ -x "$bin" ]] || { err "Test binary not found. Run '$0 build' first."; exit 1; }
    "$bin"
    ok "All tests passed."
}

# --------------- coverage ----------------------------------------------------
cmd_coverage() {
    local open_report=false
    local mem_args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --open)        open_report=true ;;
            --mem-backend) shift; mem_args+=(--mem-backend "${1:-}") ;;
            *) err "Unknown coverage option: $1 (use [--mem-backend X] [--open])"; exit 1 ;;
        esac
        shift
    done

    require_cmd lcov; require_cmd genhtml

    section "Coverage: build → test → report"
    cmd_build --gcc --coverage "${mem_args[@]}"
    cmd_test

    cd "${BUILD_DIR}"

    # lcov 2.0 (Ubuntu 24.04) changed --rc syntax and geninfo is much
    # stricter about gcov data from GCC 13+.  Build options that work for
    # both lcov 1.x and 2.x.
    # NOTE: genhtml accepts a smaller set of --ignore-errors types than
    # lcov/geninfo, so we keep separate arrays.
    local lcov_ver
    lcov_ver=$(lcov --version 2>&1 | sed -n 's/.*LCOV version \([0-9]*\).*/\1/p')
    lcov_ver="${lcov_ver:-1}"
    local lcov_rc=(--rc lcov_branch_coverage=1)
    local lcov_ignore=()
    local genhtml_ignore=()
    if [[ "$lcov_ver" -ge 2 ]]; then
        lcov_rc=(--rc branch_coverage=1)
        lcov_ignore=(--ignore-errors mismatch
                     --ignore-errors inconsistent
                     --ignore-errors gcov
                     --ignore-errors unused
                     --ignore-errors empty
                     --ignore-errors negative
                     --ignore-errors count
                     --ignore-errors source)
        genhtml_ignore=(--ignore-errors source
                        --ignore-errors unmapped
                        --ignore-errors unused)
    fi

    lcov --capture --directory . --output-file coverage_raw.info \
         "${lcov_rc[@]}" "${lcov_ignore[@]}"
    lcov --remove coverage_raw.info \
         '*/externals/*' '*/tests/*' '*/backends/cbor/src/*' '/usr/*' \
         --output-file coverage.info "${lcov_rc[@]}" "${lcov_ignore[@]}"

    genhtml coverage.info --output-directory coverage_html \
            --branch-coverage --title "libedhoc code coverage" \
            "${genhtml_ignore[@]}"

    echo ""
    echo "=== Coverage Summary ==="
    lcov --summary coverage.info "${lcov_rc[@]}" "${lcov_ignore[@]}"
    ok "\nHTML report: ${BUILD_DIR}/coverage_html/index.html"

    if [[ "$open_report" == true ]]; then
        xdg-open "${BUILD_DIR}/coverage_html/index.html" 2>/dev/null \
            || open "${BUILD_DIR}/coverage_html/index.html" 2>/dev/null \
            || echo "Open the report manually."
    fi
}

# --------------- sanitizers --------------------------------------------------
cmd_sanitizers() {
    local variant="asan-ubsan"
    local mem_args=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            asan-ubsan|asan) variant="$1" ;;
            --mem-backend)   shift; mem_args+=(--mem-backend "${1:-}") ;;
            *) err "Unknown sanitizer option: $1 (use asan-ubsan [--mem-backend X])"; exit 1 ;;
        esac
        shift
    done

    case "$variant" in
        asan-ubsan|asan)
            section "Sanitizers: ASan + UBSan (GCC)"
            cmd_build --gcc --sanitizers "${mem_args[@]}"
            ;;
        *) err "Unknown sanitizer variant: $variant (use asan-ubsan)"; exit 1 ;;
    esac
    cmd_test
}

# --------------- valgrind ----------------------------------------------------
cmd_valgrind() {
    require_cmd valgrind
    section "Valgrind memcheck + DRD"

    # Valgrind <= 3.19 does not support DWARF5 (GCC 11+ default).
    rm -rf "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"
    # Experimental PQC is OFF here: liboqs dispatches hand-written AVX2/AVX-512
    # ML-KEM code at runtime, and Valgrind cannot decode some of those opcodes
    # (SIGILL / exit 132 on AVX-512-capable runners). It carries no memcheck
    # value, so exclude it from the Valgrind job (matches the coverage build). 
    cmake -B "${BUILD_DIR}" -S "${PROJECT_DIR}" \
        "${KCONFIG_OPTIONS[@]}" \
        "${MBEDTLS_OPTIONS[@]}" \
        -DLIBEDHOC_ENABLE_TESTS=ON \
        -DLIBEDHOC_ENABLE_EXPERIMENTAL_PQC=OFF \
        -DCMAKE_C_COMPILER=gcc \
        -DCMAKE_BUILD_TYPE=Debug \
        "-DCMAKE_C_FLAGS=-gdwarf-4"
    cmake_build

    local bin
    bin="$(test_binary)"

    valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
             --error-exitcode=1 -s "$bin"
    ok "Memcheck passed."

    valgrind --tool=drd --show-stack-usage=yes \
             --error-exitcode=1 -s "$bin"
    ok "DRD passed."
}

# --------------- cppcheck ----------------------------------------------------
cmd_cppcheck() {
    require_cmd cppcheck
    section "Cppcheck"
    cd "${PROJECT_DIR}"
    cppcheck --enable=warning,style --inline-suppr --error-exitcode=1 \
        -I include/ -I library/internal/ -I backends/cbor/include/ \
        library/core/*.c
    ok "Cppcheck passed."
}

# --------------- clang-tidy --------------------------------------------------
cmd_clang_tidy() {
    local ct
    ct=$(command -v clang-tidy 2>/dev/null \
         || command -v clang-tidy-18 2>/dev/null \
         || command -v clang-tidy-17 2>/dev/null \
         || command -v clang-tidy-16 2>/dev/null \
         || command -v clang-tidy-15 2>/dev/null \
         || command -v clang-tidy-14 2>/dev/null) \
        || { err "clang-tidy not found"; exit 1; }
    section "Clang-tidy ($(basename "$ct"))"

    if [[ ! -f "${BUILD_DIR}/compile_commands.json" ]] \
       || ! grep -q '"clang"' "${BUILD_DIR}/compile_commands.json" 2>/dev/null; then
        echo "Building with Clang compile_commands.json..."
        cmake_configure \
            -DLIBEDHOC_ENABLE_TESTS=ON \
        -DLIBEDHOC_ENABLE_EXPERIMENTAL_PQC=ON \
            -DCMAKE_C_COMPILER=clang \
            -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
            -G Ninja
        cmake_build
    fi

    cd "${PROJECT_DIR}"
    "$ct" -p "${BUILD_DIR}" \
        library/core/edhoc.c \
        library/core/edhoc_message_1.c \
        library/core/edhoc_message_2.c \
        library/core/edhoc_message_3.c \
        library/core/edhoc_message_4.c \
        library/core/edhoc_message_error.c \
        library/core/edhoc_exporter.c \
        library/core/edhoc_common.c \
        library/core/edhoc_coap.c \
        library/cipher_suites/edhoc_cipher_suite.c \
        library/cipher_suites/cipher_suite_0/edhoc_cipher_suite_0.c \
        library/cipher_suites/cipher_suite_2/edhoc_cipher_suite_2.c \
        library/cipher_suites/cipher_suite_24/edhoc_cipher_suite_24.c
    ok "Clang-tidy passed."
}

# --------------- fuzz --------------------------------------------------------
cmd_fuzz() {
    local duration="${1:-60}"
    section "Fuzzing (${duration}s per target)"
    cmd_build --fuzz
    local found=0
    for target in "${BUILD_DIR}"/tests/fuzz/fuzz_*; do
        [[ -x "$target" ]] || continue
        found=1
        echo "--- Fuzzing $(basename "$target") ---"
        timeout "$duration" "$target" -max_total_time=$((duration - 5)) || true
    done
    [[ $found -eq 1 ]] || { err "No fuzz targets found in ${BUILD_DIR}/tests/fuzz/"; exit 1; }
    ok "Fuzzing complete."
}

# --------------- format ------------------------------------------------------
cmd_format() {
    require_cmd clang-format
    require_cmd git
    cd "${PROJECT_DIR}"

    local check=false
    for arg in "$@"; do
        case "$arg" in
            --check) check=true ;;
            *) err "Unknown format option: $arg"; exit 1 ;;
        esac
    done

    local files=()
    mapfile -t files < <(git ls-files '*.c' '*.h' ':!:backends/**')
    [[ ${#files[@]} -gt 0 ]] || { err "No source files found."; exit 1; }

    if [[ "$check" == true ]]; then
        section "Checking source code formatting"
        clang-format --dry-run --Werror --style=file "${files[@]}"
        ok "Formatting check passed."
    else
        section "Formatting source code"
        clang-format -i --style=file "${files[@]}"
        ok "Formatting complete."
    fi
}

# --------------- benchmark ---------------------------------------------------
# Benchmarking has moved to the Zephyr sample/benchmark app (native_sim).
# Build and run locally with:
#   west build -b native_sim sample/benchmark -p always
#   ./build/zephyr/zephyr.exe

# --------------- header hygiene ----------------------------------------------
# Installed public headers must never include a private *_internal.h header.
cmd_check_headers() {
    section "Public header hygiene"
    cd "${PROJECT_DIR}"
    local offenders
    offenders=$(grep -rEn '#[[:space:]]*include[[:space:]]*[<"][^">]*_internal\.h[">]' include/ || true)
    if [[ -n "$offenders" ]]; then
        err "Installed public headers must not include *_internal.h:"
        err "$offenders"
        exit 1
    fi
    ok "No public header includes a private *_internal.h header."
}

# --------------- all (full local CI) -----------------------------------------
cmd_all() {
    section "Full CI pipeline"
    cmd_check_headers
    cmd_coverage
    cmd_cppcheck
    cmd_clang_tidy
    cmd_valgrind
    ok "\nAll CI steps completed successfully."
}

# --------------- help --------------------------------------------------------
show_help() {
    cat <<'EOF'
Usage: scripts/ci.sh <command> [options]

Build & Test:
  build [--gcc|--clang] [--coverage] [--sanitizers] [--fuzz] [--mem-backend X]
  test                    Run test binary
  coverage [--mem-backend X] [--open]
                          Build with gcov, run tests, generate HTML report

Analysis:
  cppcheck                Static analysis with cppcheck
  clang-tidy              Static analysis with clang-tidy
  check-headers           Public headers must not include *_internal.h
  valgrind                Memcheck + DRD
  sanitizers [asan-ubsan] [--mem-backend X]  Build + test under sanitizers
  fuzz [seconds]          Build + run fuzz targets (default: 60s each)

Quality:
  format [--check]        Run clang-format on all tracked sources
                          (--check = dry-run mirroring the CI / Format job)

Memory backend (--mem-backend), maps to -DCONFIG_LIBEDHOC_MEM_BACKEND=N:
  stack                   0: C99 VLA / _alloca (default when omitted)
  heap                    1: calloc / free
  custom                  2: link-time edhoc_mem_alloc / edhoc_mem_free hooks
                          (module tests provide an instrumented allocator)

Pipeline:
  all                     Run full CI: coverage, cppcheck, clang-tidy, valgrind

Examples:
  scripts/ci.sh build --gcc              # GCC debug build
  scripts/ci.sh build --gcc --sanitizers    # GCC + ASan/UBSan
  scripts/ci.sh build --gcc --mem-backend heap   # GCC, heap allocator
  scripts/ci.sh sanitizers --mem-backend custom  # ASan/UBSan, custom allocator
  scripts/ci.sh coverage --open          # Coverage with browser
  scripts/ci.sh coverage --mem-backend custom  # Coverage incl. OOM paths
  scripts/ci.sh all                      # Full local CI
EOF
}

# --------------- main --------------------------------------------------------
main() {
    [[ $# -eq 0 ]] && { show_help; exit 0; }

    case "$1" in
        build)       shift; cmd_build "$@" ;;
        test)        cmd_test ;;
        coverage)    shift; cmd_coverage "$@" ;;
        sanitizers)  shift; cmd_sanitizers "$@" ;;
        valgrind)    cmd_valgrind ;;
        cppcheck)    cmd_cppcheck ;;
        clang-tidy)  cmd_clang_tidy ;;
        check-headers) cmd_check_headers ;;
        fuzz)        shift; cmd_fuzz "$@" ;;
        format)      shift; cmd_format "$@" ;;
        all)         cmd_all ;;
        --help|-h)   show_help ;;
        *)           err "Unknown command: $1"; show_help; exit 1 ;;
    esac
}

main "$@"

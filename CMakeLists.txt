# =============================================================================
# libedhoc — EDHOC (RFC 9528) implementation.
#
# Standalone (host) build. The Zephyr build enters through zephyr/CMakeLists.txt
# and never reads this file.
# =============================================================================

cmake_minimum_required(VERSION 3.21)
project(libedhoc VERSION 2.1.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

include(GNUInstallDirs)

# --- Options -----------------------------------------------------------------

# Tests default ON only when libedhoc is the top-level project.
option(LIBEDHOC_ENABLE_TESTS "Build module tests" ${PROJECT_IS_TOP_LEVEL})
option(LIBEDHOC_BUILD_EXTERNAL_DEPS "Use vendored submodule dependencies"  ON)
option(LIBEDHOC_ENABLE_COVERAGE     "Code coverage instrumentation (gcov)" OFF)
option(LIBEDHOC_ENABLE_SANITIZERS   "AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(LIBEDHOC_ENABLE_FUZZING      "libFuzzer fuzz targets (Clang)"       OFF)

# Included at top scope so libedhoc_target_warnings() is visible in every subdirectory.
include(cmake/warnings.cmake)

# --- Targets -----------------------------------------------------------------

# include/ sets the CONFIG_* cache defaults that externals/ gates on, so it must
# be processed before dependencies.cmake.
add_subdirectory(include)
include(cmake/dependencies.cmake)
add_subdirectory(backends)
add_subdirectory(library)

if(LIBEDHOC_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
if(LIBEDHOC_ENABLE_FUZZING)
    add_subdirectory(tests/linux/fuzz)
endif()

# --- Install / packaging -----------------------------------------------------

# Only meaningful for a standalone install against system dependencies.
if(PROJECT_IS_TOP_LEVEL AND NOT LIBEDHOC_BUILD_EXTERNAL_DEPS)
    include(CMakePackageConfigHelpers)
    # LIBEDHOC_CIPHER_SUITE_SOURCES is set in library/ and does not reach here.
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/sources.cmake)
    set(LIBEDHOC_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/libedhoc)

    # Backends are PRIVATE on the core but still appear in the export, so they
    # have to be installed with it.
    install(TARGETS libedhoc libedhoc_api
                    backend_cbor backend_memory backend_log
                    libedhoc_cipher_suites
        EXPORT  libedhoc-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

    install(EXPORT libedhoc-targets
        NAMESPACE   libedhoc::
        DESTINATION ${LIBEDHOC_CMAKE_DIR})

    # Public headers and the generated config, flat in <prefix>/include.
    install(DIRECTORY include/ ${LIBEDHOC_GENERATED_DIR}/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN "*.h")

    # Backend and internal headers are included unqualified by the reference
    # cipher-suite sources, so a consumer recompiling them needs these too.
    install(DIRECTORY backends/cbor/include/ backends/memory/include/
                      backends/log/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN "*.h")
    install(FILES library/internal/edhoc_macros_internal.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(DIRECTORY library/cipher_suites/cipher_suite_0/
                      library/cipher_suites/cipher_suite_2/
                      library/cipher_suites/cipher_suite_24/
                      library/cipher_suites/cipher_suite_pqc_1/
                      library/cipher_suites/common/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN "*.h")

    # Reference cipher-suite sources are examples, not library code.
    install(FILES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
        DESTINATION ${CMAKE_INSTALL_DATADIR}/libedhoc/cipher_suites/src)

    # zcbor is PUBLIC on backend_cbor, so find_package(libedhoc) must re-resolve it.
    configure_package_config_file(
        cmake/project-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/libedhoc-config.cmake
        INSTALL_DESTINATION ${LIBEDHOC_CMAKE_DIR})
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/libedhoc-config-version.cmake
        COMPATIBILITY SameMajorVersion)
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/libedhoc-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/libedhoc-config-version.cmake
        DESTINATION ${LIBEDHOC_CMAKE_DIR})
endif()

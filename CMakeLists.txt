cmake_minimum_required(VERSION 3.21)
project(libedhoc VERSION 1.16.0 LANGUAGES C)

# The public headers use C11 anonymous unions, so the library is C11. (The old
# `set_property(GLOBAL PROPERTY C_STANDARD 99)` was a no-op — C_STANDARD is a
# target property — so this was silently compiling as the gnu11 default.)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

include(GNUInstallDirs)

# --- Options -----------------------------------------------------------------
# Tests default ON only when libedhoc is the top-level project: a parent doing
# add_subdirectory()/FetchContent gets the library, not the tests.
option(LIBEDHOC_ENABLE_TESTS "Build module tests" ${PROJECT_IS_TOP_LEVEL})
option(LIBEDHOC_BUILD_EXTERNAL_DEPS "Use vendored submodule dependencies"  ON)
option(LIBEDHOC_ENABLE_COVERAGE     "Code coverage instrumentation (gcov)" OFF)
option(LIBEDHOC_ENABLE_SANITIZERS   "AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(LIBEDHOC_ENABLE_FUZZING      "libFuzzer fuzz targets (Clang)"       OFF)
option(LIBEDHOC_ENABLE_EXPERIMENTAL_PQC "Build experimental PQC cipher suite 1 helper (liboqs)" OFF)

# --- Shared CMake helpers ----------------------------------------------------
# Defined at top scope so libedhoc_target_warnings() is visible in every
# add_subdirectory() (library, tests, fuzz).
include(cmake/warnings.cmake)

# --- Dependencies (submodules OR find_package) -------------------------------
include(cmake/dependencies.cmake)

# --- Targets -----------------------------------------------------------------
# Order matters: backends define backend_* (used by include/library/helpers).
add_subdirectory(backends)
add_subdirectory(include)
add_subdirectory(helpers)
add_subdirectory(library)

if(LIBEDHOC_ENABLE_TESTS)
    add_subdirectory(tests)
endif()
if(LIBEDHOC_ENABLE_FUZZING)
    add_subdirectory(tests/fuzz)
endif()

# --- Install / packaging -----------------------------------------------------
# Only meaningful for a standalone install against system dependencies.
if(PROJECT_IS_TOP_LEVEL AND NOT LIBEDHOC_BUILD_EXTERNAL_DEPS)
    include(CMakePackageConfigHelpers)
    set(LIBEDHOC_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/libedhoc)

    # All targets reachable from the export must be installed together. Backends
    # are PRIVATE on the core but still appear as $<LINK_ONLY:> in the export, so
    # they have to travel with it.
    install(TARGETS libedhoc libedhoc_api
                    backend_cbor backend_memory backend_log
                    libedhoc_helpers
        EXPORT  libedhoc-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

    # NAMESPACE makes the imported targets match the in-tree aliases exactly:
    # consumers always write libedhoc::edhoc, whether via find_package,
    # add_subdirectory, or FetchContent.
    install(EXPORT libedhoc-targets
        NAMESPACE   libedhoc::
        DESTINATION ${LIBEDHOC_CMAKE_DIR})

    # Public headers + generated config, flat in <prefix>/include. Backend +
    # helper headers go here too, so the helper sources can be recompiled by a
    # downstream consumer (they #include "edhoc_backend_log.h" unqualified).
    install(DIRECTORY include/ ${LIBEDHOC_GENERATED_DIR}/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN "*.h")
    install(DIRECTORY backends/cbor/include/ backends/memory/include/
                      backends/log/include/ helpers/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN "*.h")

    # Helper *sources* are examples/convenience, not library code → share/,
    # never the cmake-package dir.
    install(FILES ${LIBEDHOC_HELPERS_SOURCES}
        DESTINATION ${CMAKE_INSTALL_DATADIR}/libedhoc/helpers/src)

    # find_package(libedhoc) re-resolves zcbor (PUBLIC on backend_cbor) — without
    # this, the imported backend_cbor would reference an unknown 'zcbor' target.
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

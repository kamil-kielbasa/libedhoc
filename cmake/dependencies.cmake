# =============================================================================
# Third-party dependencies. Two supported modes:
#   * LIBEDHOC_BUILD_EXTERNAL_DEPS=ON  (default) — vendored git submodules.
#   * LIBEDHOC_BUILD_EXTERNAL_DEPS=OFF           — system/installed packages
#     located with find_package(); used by the sandbox/packaging flow.
#
# The Zephyr build does not enter the root CMakeLists, so this file applies to
# the standalone build only.
# =============================================================================

if(LIBEDHOC_BUILD_EXTERNAL_DEPS)
    add_subdirectory(externals)
else()
    set(ZCBOR_IMPORT_TARGETS ON)
    find_package(zcbor REQUIRED CONFIG)
endif()

# --- Migration path (exemplar) ----------------------------------------------
# When dropping submodules, the modern replacement is FetchContent with
# FIND_PACKAGE_ARGS (CMake >= 3.24): a system package is preferred when
# present, otherwise the sources are fetched — and distros can force
# find_package() with -DFETCHCONTENT_TRY_FIND_PACKAGE_MODE=ALWAYS:
#
#   include(FetchContent)
#   FetchContent_Declare(zcbor
#       GIT_REPOSITORY https://github.com/NordicSemiconductor/zcbor.git
#       GIT_TAG        0.9.1
#       FIND_PACKAGE_ARGS CONFIG)
#   FetchContent_MakeAvailable(zcbor)

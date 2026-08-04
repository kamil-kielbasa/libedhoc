# =============================================================================
# Third-party dependencies for the standalone build.
#
# LIBEDHOC_BUILD_EXTERNAL_DEPS=ON  — vendored git submodules (default).
# LIBEDHOC_BUILD_EXTERNAL_DEPS=OFF — installed packages via find_package().
# =============================================================================

if(LIBEDHOC_BUILD_EXTERNAL_DEPS)
    add_subdirectory(externals)
else()
    set(ZCBOR_IMPORT_TARGETS ON)
    find_package(zcbor REQUIRED CONFIG)
endif()

# =============================================================================
# Standalone zcbor build for the sandbox / find_package install flow.
# Source lists come from cmake/externals_sources.cmake.
# =============================================================================

cmake_minimum_required(VERSION 3.20)
project(zcbor)
enable_language(C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/externals_sources.cmake)

# --- Library -----------------------------------------------------------------

add_library(${PROJECT_NAME} STATIC ${LIBEDHOC_ZCBOR_SOURCES})

target_compile_definitions(${PROJECT_NAME} PRIVATE ${LIBEDHOC_ZCBOR_COMPILE_DEFINITIONS})
target_include_directories(${PROJECT_NAME} PUBLIC ${LIBEDHOC_ZCBOR_INCLUDE_DIR})

# --- Install -----------------------------------------------------------------

include(GNUInstallDirs)

install(
    DIRECTORY ${LIBEDHOC_ZCBOR_INCLUDE_DIR}/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(
    TARGETS ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(
    FILES zcbor-config.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zcbor)

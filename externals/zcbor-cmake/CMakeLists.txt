cmake_minimum_required(VERSION 3.20)
project(zcbor)
enable_language(C)

if(NOT DEFINED ZCBOR_PATH)
    message(FATAL_ERROR "ZCBOR_PATH is not defined")
endif()

add_library(${PROJECT_NAME} 
    STATIC
        ${ZCBOR_PATH}/src/zcbor_common.c
        ${ZCBOR_PATH}/src/zcbor_decode.c
        ${ZCBOR_PATH}/src/zcbor_encode.c)

target_compile_definitions(${PROJECT_NAME} PUBLIC ZCBOR_CANONICAL)
target_include_directories(${PROJECT_NAME} PUBLIC ${ZCBOR_PATH}/include)

include(GNUInstallDirs)
install(
    DIRECTORY ${ZCBOR_PATH}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(
    TARGETS ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(
    FILES zcbor-config.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zcbor
)

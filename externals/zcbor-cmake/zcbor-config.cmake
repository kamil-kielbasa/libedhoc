cmake_minimum_required(VERSION 3.20)

# Create imported target zcbor
add_library(zcbor STATIC IMPORTED GLOBAL)

set_target_properties(zcbor PROPERTIES
    IMPORTED_LINK_INTERFACE_LANGUAGES "C"
    IMPORTED_LOCATION "${CMAKE_CURRENT_LIST_DIR}/../../libzcbor.a"
)
set_target_properties(zcbor PROPERTIES
    INTERFACE_COMPILE_DEFINITIONS "ZCBOR_CANONICAL"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_LIST_DIR}/../../../include"
)

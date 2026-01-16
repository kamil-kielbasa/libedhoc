project(libedhoc_api)

add_library(${PROJECT_NAME} INTERFACE)

if (NOT TARGET zephyr_interface)
    target_include_directories(${PROJECT_NAME} INTERFACE
                                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../port/log/linux>)
else()
    target_include_directories(${PROJECT_NAME} INTERFACE
                               ${CMAKE_CURRENT_SOURCE_DIR}/../port/log/zephyr)
endif()

target_include_directories(${PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

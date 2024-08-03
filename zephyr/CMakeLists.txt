if(CONFIG_LIBEDHOC_ENABLE)
    # Name must be synchronized with ${PROJECT_NAME} of root CMakeLists.txt
    zephyr_library_named(libedhoc)
    add_subdirectory(.. build)
    # Name must be synchronized with ${PROJECT_NAME} of include CMakeLists.txt
    target_link_libraries(zephyr_interface INTERFACE libedhoc_api)
endif(CONFIG_LIBEDHOC_ENABLE)

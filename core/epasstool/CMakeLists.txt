add_executable(epasstool
    epasstool.c
    readlog.c
    read.c
    print.c
    printlog.c
    load.c
    # Test passes
    test_pass1.c
)

target_compile_definitions(epasstool PRIVATE -DEPASS_VERSION="${CMAKE_PROJECT_VERSION}")

target_link_libraries(epasstool bpf epass)
set_target_properties(epasstool PROPERTIES OUTPUT_NAME "epass")
install (TARGETS epasstool)

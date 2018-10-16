cmake_minimum_required(VERSION 3.5)

enable_testing()

set(POLESTAR_PAK_DIR ${CMAKE_SOURCE_DIR})

if(UNIX OR LINUX OR MINGW OR APPLE)
    list(APPEND CMAKE_MODULE_PATH "${POLESTAR_PAK_DIR}/src/cmake/")
    include(CodeCoverage)
    APPEND_COVERAGE_COMPILER_FLAGS()
    # COVERAGE_GCOVR_EXCLUDE_DIRS is a regex with directories to exclude from coverage report
    set(COVERAGE_GCOVR_EXCLUDES
            '${POLESTAR_PAK_DIR}/extern_libs'
            '${POLESTAR_PAK_DIR}/server_app'
            '${POLESTAR_PAK_DIR}/src/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/chunk/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/crypto/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/filesystem/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/kline/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/lzss/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/cmd_interpreter/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/pak_messaging/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/sbl/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/tone_gen/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/tone_det/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/transport/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/ui_message/tests'
            '${POLESTAR_PAK_DIR}/src/common_src/pakp_sm/tests'
            '${POLESTAR_PAK_DIR}/src/platform/flash/tests'
            '${POLESTAR_PAK_DIR}/src/tools/progpak/tests'
            '${POLESTAR_PAK_DIR}/projects/testapp/'
    )

    if (LINUX OR WIN32)
        if (NOT MINGW)
            set(FREERTOS_TEST freertos_test)
        endif(NOT MINGW)
    endif(LINUX OR WIN32)

    # SETUP_TARGET_FOR_COVERAGE_GCOVR_HTML(
    #     NAME ctest_coverage                    # New target name
    #     EXECUTABLE ctest -j ${PROCESSOR_COUNT} # Executable in PROJECT_BINARY_DIR
    #     DEPENDENCIES executable_target         # Dependencies to build first
    SETUP_TARGET_FOR_COVERAGE_GCOVR_HTML(
            NAME ctest_coverage
            EXECUTABLE ctest -j 4
            DEPENDENCIES
                ble_handshaking_test
                chunk_test
                cmd_interpreter_test
                crypto_test
                filesystem_test
                flash_test
                kline_test
                lzss_test
                polestar_pak
                progpak_test
                sbl_test
                test_pak_messaging
                tone_det_test
                tone_gen_test
                transport_test
                ui_message_test
                ${FREERTOS_TEST}
    )
    SETUP_TARGET_FOR_COVERAGE_GCOVR_XML(
            NAME cobertura
    )
endif()

add_subdirectory(src)
add_subdirectory(projects)


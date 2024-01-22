cmake_minimum_required(VERSION 3.14)

project(authenticode_parser VERSION 1.0.0 LANGUAGES C)

find_package(OpenSSL 1.1.1 REQUIRED)

include(GNUInstallDirs)

add_library(authenticode STATIC
        src/authenticode.c
        src/helper.c
        src/structs.c
        src/countersignature.c
        src/certificate.c
)

include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
        target_compile_definitions(-DWORDS_BIGENDIAN)
endif()

if(MSVC)
        target_compile_options(authenticode PRIVATE /W4)
else()
        target_compile_options(authenticode PRIVATE -Wall -Wextra -Wpedantic -fpie)
endif()

target_compile_features(authenticode PRIVATE c_std_11)

target_include_directories(authenticode
        PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(authenticode
        PUBLIC
                OpenSSL::Crypto
)

install(
        DIRECTORY include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(TARGETS authenticode
        EXPORT authenticode-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/authenticode)

install(EXPORT authenticode-targets
        FILE "authenticode-targets.cmake"
        DESTINATION ${INSTALL_CONFIGDIR}
)

include(CMakePackageConfigHelpers)

configure_file(
        "authenticode-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/authenticode-config.cmake"
        @ONLY
)
install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/authenticode-config.cmake"
        DESTINATION ${INSTALL_CONFIGDIR}
)

if(BUILD_TESTS) 
        enable_testing()
        add_subdirectory(tests)
endif()

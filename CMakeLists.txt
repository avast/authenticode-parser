cmake_minimum_required(VERSION 3.10)

project(authenticode_parser VERSION 1.0.0 LANGUAGES C)

find_package(OpenSSL 1.0.1 REQUIRED)

add_library(authenticode STATIC
        src/authenticode.c
        src/helper.c
        src/structs.c
        src/countersignature.c
        src/certificate.c
)

add_library(authenticode::parser ALIAS authenticode)

target_compile_options(authenticode PRIVATE -Wall -Wextra -pedantic)
target_compile_features(authenticode PRIVATE c_std_11)

target_include_directories(authenticode
        PUBLIC
                $<INSTALL_INTERFACE:include>
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src
)


target_link_libraries(authenticode
        PRIVATE
                OpenSSL::Crypto
)

include(GNUInstallDirs)

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

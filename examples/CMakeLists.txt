cmake_minimum_required(VERSION 3.14)

project(authenticode_dumper LANGUAGES C)

add_executable(authenticode_dumper authenticode_dumper.c)
target_compile_options(authenticode_dumper PRIVATE -Wall)

find_package(authenticode REQUIRED)

target_link_libraries(authenticode_dumper
        PUBLIC 
                authenticode
)

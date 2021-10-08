cmake_minimum_required(VERSION 3.10)

project(authenicode_dumper LANGUAGES C)

add_executable(authenticode_dumper authenticode_dumper.c)
target_compile_options(authenticode_dumper PRIVATE -Wall -Wextra -pedantic)

find_package(authenticode REQUIRED)
# I feel like we should be able to get OpenSSL from Authenticode package...
find_package(OpenSSL REQUIRED)

target_link_libraries(authenticode_dumper 
	PUBLIC authenticode
	PRIVATE OpenSSL::Crypto)

project(test)

set(CMAKE_CXX_STANDARD 11)

include(FetchContent)
FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        e2239ee6043f73722e7aa812a459f54a28552929 # release-1.11.0
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

add_executable(tests 
        integration/test.cpp
        unit/countersignature.cpp
        unit/certificate.cpp
        unit/helper.cpp)

target_link_libraries(tests 
        PRIVATE 
                gtest_main
                authenticode)

include(GoogleTest)
gtest_add_tests(TARGET tests)
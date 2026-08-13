cmake_minimum_required(VERSION 4.2)
project(zeus VERSION 1.0.1 LANGUAGES CXX)

set(CMAKE_C_COMPILER "/usr/bin/clang-22")
set(CMAKE_CXX_COMPILER "/usr/bin/clang++-22")


set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-stdlib=libc++)
add_link_options(-stdlib=libc++)
link_libraries(c++ c++abi)

include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(zeus main.cpp
        zeus-core/lib/zeus.cc
        zeus-core/lib/zeus.hh
        zeus-engine/lib/zeus_engine.cc
        zeus-engine/lib/zeus_engine.hh
        zeus-core/lib/zeus_contract.hh
        zeus-engine/lib/zeus_database.cc
        zeus-engine/lib/zeus_database.hh
        zeus-engine/lib/zeus_proto.cc
        zeus-engine/lib/zeus_proto.hh
        zeus-engine/lib/zeus_net.cc
        zeus-engine/lib/zeus_net.hh
        zeus-core/lib/zeus_transport.hh
        zeus-core/lib/bfg.c
        zeus-core/lib/bfg.h
        zeus-core/lib/crc32.c
        zeus-core/lib/crc32.h
        zeus-core/lib/d3des.c
        zeus-core/lib/d3des.h
        zeus-core/lib/hmacmd5.c
        zeus-core/lib/hmacmd5.h
        zeus-core/lib/libpq-fe.h
        zeus-core/lib/ntlm.c
        zeus-core/lib/ntlm.h
        zeus-core/lib/performance.h
        zeus-core/lib/postgres_ext.h
        zeus-core/lib/pw-inspector.c
        zeus-core/lib/sasl.c
        zeus-core/lib/sasl.h)



add_executable(zeus_engine_tests
        zeus-engine/tests/test_zeus_net.cc
        zeus-engine/tests/test_zeus_proto.cc
        zeus-engine/tests/test_zeus_database.cc
        zeus-engine/tests/test_logger.cc
        zeus-engine/tests/test_proxy_pool.cc
        zeus-engine/tests/test_proxy_handshake.cc
        zeus-engine/tests/test_connection.cc
        zeus-engine/tests/test_ipc_channel.cc
        zeus-engine/tests/test_reporting.cc
        zeus-engine/tests/test_module_registry_and_engine_run.cc
        zeus-engine/tests/test_connection_tls.cc
)
target_link_libraries(zeus_engine_tests PRIVATE zeus_core GTest::gtest_main GTest::gmock)

add_executable(zeus_core_tests
        zeus-core/tests/test_contract.cc
        zeus-core/tests/test_stats_board.cc
        zeus-core/tests/test_options_parser.cc
        zeus-core/tests/test_restore_session.cc
        zeus-core/tests/test_credential_source.cc
        zeus-core/tests/test_target_expander.cc
        zeus-core/tests/test_scheduler_smoke.cc
        zeus-core/tests/test_fake_transport_contract.cc
        zeus-core/tests/test_signal_guard.cc
)
target_link_libraries(zeus_core_tests PRIVATE zeus_core GTest::gtest_main GTest::gmock)

include(GoogleTest)
gtest_discover_tests(zeus_engine_tests)
gtest_discover_tests(zeus_core_tests)

option(ZEUS_ENABLE_SANITIZERS "Build with ASan+UBSan" OFF)
if(ZEUS_ENABLE_SANITIZERS)
    target_compile_options(zeus_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(zeus_core PUBLIC -fsanitize=address,undefined)
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wshadow
        -Wformat=2
        -Werror=return-type
        -Werror=uninitialized
        -Wno-unused-parameter
        $<$<CONFIG:Debug>:-g3 -O0 -fsanitize=address,undefined -fno-omit-frame-pointer>
        $<$<CONFIG:Release>:-O3 -DNDEBUG -march=native>
        $<$<CONFIG:RelWithDebInfo>:-O2 -g3>
)


add_link_options($<$<CONFIG:Debug>:-fsanitize=address,undefined>)


find_package(Boost REQUIRED COMPONENTS filesystem)

target_include_directories(zeus PRIVATE ${Boost_INCLUDE_DIRS})


find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

find_library(LIBSSH_FOUND ssh)
find_library(LIBFREERDP  freerdp2)
find_library(LIBMCACHED memcached)
find_library(LIBPQ pq)
find_library(LIBMYSQL mysqlclient)
find_library(LIBFIREBIRD fbclient)
find_library(LIBPCRE pcre2-8)


option(ZEUS_BUILD_TESTS "Build unit tests" OFF)
if(ZEUS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()





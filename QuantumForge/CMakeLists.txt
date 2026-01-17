cmake_minimum_required(VERSION 3.15)
project(QuantumForge VERSION 2.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(QF_BUILD_STATIC "Build static binaries" OFF)
option(QF_ENABLE_HARDENING "Enable security hardening flags" ON)
option(QF_ENABLE_TESTS "Build unit tests" ON)
option(QF_ENABLE_FUZZING "Build fuzzing targets" OFF)
option(QF_ENABLE_SANITIZERS "Build with sanitizers (ASAN/UBSAN)" OFF)
option(QF_ENABLE_LTO "Enable Link Time Optimization" ON)
option(QF_ENABLE_PGO "Enable Profile Guided Optimization" OFF)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

if(NOT APPLE AND NOT WIN32)
    find_library(DL_LIBRARY dl REQUIRED)
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/junk.h
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/generate_junk.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Generating polymorphic junk code"
)

add_custom_target(generate_junk DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/junk.h)

if(UNIX AND NOT APPLE)
    add_executable(quantumserver quantumserver.c)
    add_dependencies(quantumserver generate_junk)
    
    target_link_libraries(quantumserver
        PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        CURL::libcurl
        ${CMAKE_DL_LIBS}
        Threads::Threads
    )
    
    target_compile_definitions(quantumserver PRIVATE _GNU_SOURCE)
    
    if(QF_ENABLE_HARDENING)
        target_compile_options(quantumserver PRIVATE
            -fstack-protector-strong
            -fPIE
            -fvisibility=hidden
            -D_FORTIFY_SOURCE=2
            -Wall
            -Wextra
            -Werror=format-security
            -Werror=implicit-function-declaration
        )
        
        target_link_options(quantumserver PRIVATE
            -pie
            -Wl,-z,relro
            -Wl,-z,now
            -Wl,-z,noexecstack
        )
    endif()
    
    if(QF_ENABLE_LTO)
        set_property(TARGET quantumserver PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
    
    if(QF_BUILD_STATIC)
        target_link_options(quantumserver PRIVATE -static)
    endif()
    
    if(QF_ENABLE_SANITIZERS)
        target_compile_options(quantumserver PRIVATE
            -fsanitize=address,undefined
            -fno-omit-frame-pointer
        )
        target_link_options(quantumserver PRIVATE
            -fsanitize=address,undefined
        )
    endif()
    
    install(TARGETS quantumserver DESTINATION bin)
endif()

if(APPLE)
    add_executable(quantum_loader_mac quantum_loader_mac.c)
    add_dependencies(quantum_loader_mac generate_junk)
    
    target_link_libraries(quantum_loader_mac
        PRIVATE
        "-framework Security"
        "-framework CoreFoundation"
        CURL::libcurl
    )
    
    if(QF_ENABLE_HARDENING)
        target_compile_options(quantum_loader_mac PRIVATE
            -fstack-protector-strong
            -fPIE
            -D_FORTIFY_SOURCE=2
            -Wall
            -Wextra
        )
        
        target_link_options(quantum_loader_mac PRIVATE -pie)
    endif()
    
    install(TARGETS quantum_loader_mac DESTINATION bin)
endif()

if(WIN32)
    add_executable(quantum_loader_win quantum_loader_win.c)
    add_dependencies(quantum_loader_win generate_junk)
    
    target_link_libraries(quantum_loader_win
        PRIVATE
        bcrypt
        winhttp
        ws2_32
        advapi32
    )
    
    if(QF_ENABLE_HARDENING)
        target_compile_options(quantum_loader_win PRIVATE
            /GS
            /DYNAMICBASE
            /guard:cf
        )
        
        target_link_options(quantum_loader_win PRIVATE
            /NXCOMPAT
            /DYNAMICBASE
            /GUARD:CF
        )
    endif()
    
    install(TARGETS quantum_loader_win DESTINATION bin)
endif()

if(QF_ENABLE_TESTS)
    enable_testing()
    
    add_executable(test_crypto_unit tests/test_crypto_unit.c)
    target_link_libraries(test_crypto_unit
        PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
    )
    target_compile_definitions(test_crypto_unit PRIVATE _GNU_SOURCE)
    add_test(NAME CryptoUnitTests COMMAND test_crypto_unit)
    
    if(UNIX AND NOT APPLE)
        add_test(NAME IntegrationTests
            COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_loader_linux.sh
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
    endif()
endif()

if(QF_ENABLE_FUZZING)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        add_executable(fuzz_base64 tests/fuzz_base64.c)
        target_compile_options(fuzz_base64 PRIVATE -fsanitize=fuzzer,address)
        target_link_options(fuzz_base64 PRIVATE -fsanitize=fuzzer,address)
        
        add_executable(fuzz_hkdf tests/fuzz_hkdf.c)
        target_link_libraries(fuzz_hkdf PRIVATE OpenSSL::Crypto)
        target_compile_options(fuzz_hkdf PRIVATE -fsanitize=fuzzer,address)
        target_link_options(fuzz_hkdf PRIVATE -fsanitize=fuzzer,address)
    endif()
endif()

if(QF_ENABLE_PGO)
    if(NOT PGO_STAGE)
        set(PGO_STAGE "generate")
    endif()
    
    if(PGO_STAGE STREQUAL "generate")
        target_compile_options(quantumserver PRIVATE -fprofile-generate)
        target_link_options(quantumserver PRIVATE -fprofile-generate)
    elseif(PGO_STAGE STREQUAL "use")
        target_compile_options(quantumserver PRIVATE -fprofile-use)
        target_link_options(quantumserver PRIVATE -fprofile-use)
    endif()
endif()

set(CPACK_PACKAGE_NAME "QuantumForge")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Cross-Platform In-Memory Payload Orchestrator")
set(CPACK_PACKAGE_VENDOR "QuantumForge Project")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_GENERATOR "TGZ;DEB;RPM")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "QuantumForge")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl3, libcurl4")

include(CPack)

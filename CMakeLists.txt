cmake_minimum_required(VERSION 3.23)
project(tiny-steam-client)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)

include_directories (
    ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${HL2SDK-CSGO}/common/protobuf-2.5.0/src
    ${ASIO-SRC}/include
    ${CRYPTOPP-SRC}
)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src MAIN_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src/bitbuf BITBUF_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src/proto PROTO_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src/utility UTILITY_SRC)
set(SRC_LIST ${MAIN_SRC} ${BITBUF_SRC} ${PROTO_SRC} ${UTILITY_SRC})

if(MSVC)
    add_definitions(
        -D _WIN32_WINNT=0x0601
        -D _CRT_SECURE_NO_WARNINGS
        -D _GENERIC
        -D COMPILER_MSVC
        -D COMPILER_MSVC32
        -D _SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING
        -D CURL_STATICLIB
    )
    
    set(STATIC_LIB_LIST 
        cryptlib.lib
        libprotobuf.lib
        libcurl_a.lib
        msvcrt.lib
        normaliz.lib
        crypt32.lib
        wldap32.lib
    )
    
    link_directories(
        ${HL2SDK-CSGO}/lib/win32/release/vs2017
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/win32/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/win32/curl
    )
    add_compile_options(/MT)
    add_compile_options(/wd4819)
    add_link_options(/NODEFAULTLIB:libcmt.lib)

elseif(("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU"))

    add_definitions(
        -D GNUC
        -D POSIX
        -D COMPILER_GCC
        -D _GLIBCXX_USE_CXX11_ABI=0
        -D CURL_STATICLIB
    )
    
    set(STATIC_LIB_LIST 
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/linux32/libcurl.a
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/linux32/libssl.a
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/linux32/libcrypto.a
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/linux32/libcryptopp.a
        ${HL2SDK-CSGO}/lib/linux32/release/libprotobuf.a
        libpthread.so
        libdl.so
    )
        
    add_compile_options(
        -m32 
        -fcoroutines
    )
    
    add_link_options(-m32)
endif()

add_executable(tiny-steam-client ${SRC_LIST})
target_link_libraries(tiny-steam-client ${STATIC_LIB_LIST})

if(MSVC)
    set_property(DIRECTORY PROPERTY VS_STARTUP_PROJECT tiny-steam-client)
endif()

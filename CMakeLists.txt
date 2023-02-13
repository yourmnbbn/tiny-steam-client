cmake_minimum_required(VERSION 3.23)
project(tiny-steam-client)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)

include_directories (
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
    )
    
    set(STATIC_LIB_LIST 
        cryptlib.lib
        libprotobuf.lib
    )
    
    link_directories(
        ${HL2SDK-CSGO}/lib/win32/release/vs2017
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/win32/crypto
    )
    add_compile_options(/MT)
    add_compile_options(/wd4819)

endif()

add_executable(tiny-steam-client ${SRC_LIST})
target_link_libraries(tiny-steam-client ${STATIC_LIB_LIST})

if(MSVC)
    set_property(DIRECTORY PROPERTY VS_STARTUP_PROJECT tiny-steam-client)
endif()
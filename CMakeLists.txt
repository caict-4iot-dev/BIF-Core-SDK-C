cmake_minimum_required(VERSION 3.10)
project(bif-core-sdk-clang)

#set(CMAKE_C_COMPILER, "/usr/local/gcc-4.4.7/build/bin/gcc")
#set(CMAKE_CXX_COMPILER, "/usr/local/gcc-4.4.7/build/bin/g++")
set(BIFCHAIN_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(LIB_BIFCORE_SDK bifcore_sdk_clang)
execute_process(COMMAND make all WORKING_DIRECTORY ${BIFCHAIN_SRC_DIR}/3rd)

file(GLOB_RECURSE SDK_SHARED_SRC RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/*.c")
file(GLOB_RECURSE EXAMPLE_SRC RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/example/*.c")
file(GLOB_RECURSE 3RD_SRC RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/3rd/*.c")
list(REMOVE_ITEM SDK_SHARED_SRC ${3RD_SRC})
list(REMOVE_ITEM SDK_SHARED_SRC ${EXAMPLE_SRC})

include_directories(
    ${BIFCHAIN_SRC_DIR}/include
    ${BIFCHAIN_SRC_DIR}/3rd/libscrypt
    ${BIFCHAIN_SRC_DIR}/3rd/jansson-2.10/build/include
    ${BIFCHAIN_SRC_DIR}/3rd/curl-master/build/include
    ${BIFCHAIN_SRC_DIR}/3rd/ed25519-donna
    ${BIFCHAIN_SRC_DIR}/3rd/openssl/include
)
link_directories(
    ${BIFCHAIN_SRC_DIR}/3rd/openssl
    ${BIFCHAIN_SRC_DIR}/3rd/jansson-2.10/build/lib
    ${BIFCHAIN_SRC_DIR}/3rd/libscrypt
    ${BIFCHAIN_SRC_DIR}/3rd/curl-master/build/lib
    ${BIFCHAIN_SRC_DIR}/3rd/ed25519-donna/build
)

set(DEPENDS_LIBS scrypt crypto ssl bifchain_ed25519 curl jansson dl pthread)
add_library(${LIB_BIFCORE_SDK} STATIC ${SDK_SHARED_SRC})
SET_TARGET_PROPERTIES(${LIB_BIFCORE_SDK} PROPERTIES  OUTPUT_NAME "bifcore_sdk_clang")
SET_TARGET_PROPERTIES(${LIB_BIFCORE_SDK} PROPERTIES CLEAN_DIRECT_OUTPUT 1)
target_link_libraries(${LIB_BIFCORE_SDK} ${DEPENDS_LIBS})

add_library(sdk_clang_shared SHARED  ${SDK_SHARED_SRC})
SET_TARGET_PROPERTIES(sdk_clang_shared PROPERTIES  OUTPUT_NAME "bifcore_sdk_clang")
SET_TARGET_PROPERTIES(sdk_clang_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
target_link_libraries(sdk_clang_shared ${DEPENDS_LIBS})

target_compile_options(${LIB_BIFCORE_SDK}
        PUBLIC -fPIC
        PUBLIC -g
        PUBLIC -std=gnu99
)
target_compile_options(sdk_clang_shared
        PUBLIC -fPIC
        PUBLIC -g
        PUBLIC -std=gnu99
)
install(TARGETS ${LIB_BIFCORE_SDK} sdk_clang_shared 
    LIBRARY DESTINATION ${BIFCHAIN_SRC_DIR}/build/lib 
    ARCHIVE DESTINATION ${BIFCHAIN_SRC_DIR}/build/lib)

install(
    DIRECTORY ${BIFCHAIN_SRC_DIR}/include/request 
    ${BIFCHAIN_SRC_DIR}/include/response
    DESTINATION ${BIFCHAIN_SRC_DIR}/build/include
)
install(FILES ${BIFCHAIN_SRC_DIR}/include/account_service.h
        ${BIFCHAIN_SRC_DIR}/include/block_service.h         
        ${BIFCHAIN_SRC_DIR}/include/contract_service.h 
        ${BIFCHAIN_SRC_DIR}/include/transaction_service.h 
        ${BIFCHAIN_SRC_DIR}/include/general.h
        ${BIFCHAIN_SRC_DIR}/include/key_pair_entity.h
        ${BIFCHAIN_SRC_DIR}/include/key_store.h
        ${BIFCHAIN_SRC_DIR}/include/mnemonic/mnemonic.h
        ${BIFCHAIN_SRC_DIR}/include/private_key_manager.h
        ${BIFCHAIN_SRC_DIR}/include/public_key_manager.h
        ${BIFCHAIN_SRC_DIR}/include/sdscompat.h
        ${BIFCHAIN_SRC_DIR}/include/sds.h
        ${BIFCHAIN_SRC_DIR}/include/util.h
        DESTINATION ${BIFCHAIN_SRC_DIR}/build/include
)

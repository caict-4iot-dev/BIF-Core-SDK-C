#bifchain ed25519 module CmakeLists.txt -- libbifchain_ed25519.a

set(LIB_BIFCHAIN_ED25519 bifchain_ed25519)
set(BIFCHAIN_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/../openssl/build/include
)
link_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/../openssl/build/lib
)
set(DEPENDS_LIBS crypto ssl)
aux_source_directory(${BIFCHAIN_SRC_DIR} ED25519_SRC)
#aux_source_directory(${BIFCHAIN_SRC_DIR}/3rd/ed25519-donna/ ED25519_SRC)
add_library(${LIB_BIFCHAIN_ED25519} ${ED25519_SRC}) 

target_compile_options(${LIB_BIFCHAIN_ED25519} 
	PUBLIC -DASIO_STANDALONE 
	PUBLIC -fPIC
)
target_link_libraries(${LIB_BIFCHAIN_ED25519} ${DEPENDS_LIBS})

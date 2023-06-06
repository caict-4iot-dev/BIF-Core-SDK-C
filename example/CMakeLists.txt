cmake_minimum_required(VERSION 3.10)
project(example C)

set(BIFCHAIN_SRC_MAIN_DIR ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(
    ${BIFCHAIN_SRC_MAIN_DIR}/../build/include
)
link_directories(
    ${BIFCHAIN_SRC_MAIN_DIR}/../build/lib
)
set(DEPENDS_LIBS bifcore_sdk_clang dl pthread z)

add_executable(account_create_service_example account_create_service_example.c)
target_link_libraries(account_create_service_example ${DEPENDS_LIBS})

add_executable(account_get_service_example account_get_service_example.c)
target_link_libraries(account_get_service_example ${DEPENDS_LIBS})

add_executable(account_set_metadata_example account_set_metadata_example.c)
target_link_libraries(account_set_metadata_example ${DEPENDS_LIBS})

add_executable(account_set_privilege_example account_set_privilege_example.c)
target_link_libraries(account_set_privilege_example ${DEPENDS_LIBS})

add_executable(block_get_service_example block_get_service_example.c)
target_link_libraries(block_get_service_example ${DEPENDS_LIBS})

add_executable(contract_batch_invoke_example contract_batch_invoke_example.c)
target_link_libraries(contract_batch_invoke_example ${DEPENDS_LIBS})

add_executable(contract_create_example contract_create_example.c)
target_link_libraries(contract_create_example ${DEPENDS_LIBS})

add_executable(contract_get_example contract_get_example.c)
target_link_libraries(contract_get_example ${DEPENDS_LIBS})

add_executable(contract_invoke_example contract_invoke_example.c)
target_link_libraries(contract_invoke_example ${DEPENDS_LIBS})

add_executable(contract_query_example contract_query_example.c)
target_link_libraries(contract_query_example ${DEPENDS_LIBS})

add_executable(crypto_manager crypto_manager.c)
target_link_libraries(crypto_manager ${DEPENDS_LIBS})

add_executable(evaluate_batch_example evaluate_batch_example.c)
target_link_libraries(evaluate_batch_example ${DEPENDS_LIBS})

add_executable(evaluate_fee evaluate_fee.c)
target_link_libraries(evaluate_fee ${DEPENDS_LIBS})

add_executable(key_store_example key_store_example.c)
target_link_libraries(key_store_example ${DEPENDS_LIBS})

add_executable(mnemonic_example mnemonic_example.c)
target_link_libraries(mnemonic_example ${DEPENDS_LIBS})

add_executable(transaction_batch_gas_send_example transaction_batch_gas_send_example.c)
target_link_libraries(transaction_batch_gas_send_example ${DEPENDS_LIBS})

add_executable(transaction_bif_submit_example transaction_bif_submit_example.c)
target_link_libraries(transaction_bif_submit_example ${DEPENDS_LIBS})

add_executable(transaction_gas_send_example transaction_gas_send_example.c)
target_link_libraries(transaction_gas_send_example ${DEPENDS_LIBS})

add_executable(transaction_get_example transaction_get_example.c)
target_link_libraries(transaction_get_example ${DEPENDS_LIBS})
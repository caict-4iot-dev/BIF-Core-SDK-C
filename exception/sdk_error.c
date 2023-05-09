/*
 * © COPYRIGHT 2022 Corporation CAICT All rights reserved.
 *  http://www.caict.ac.cn
 *  https://bitfactory.cn
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @author: zhangzhiliang@caict.ac.cn
 * @date: 2023-03-01 16:17:18
 * @file: sdk_error.c
 */

#include "sdk_error.h"

SdkError success = {SUCCESS, {0, "Success"}};
SdkError account_create_error = {ACCOUNT_CREATE_ERROR,
                                 {11001, "Failed to create the account"}};
SdkError invalid_amount_error = {
    INVALID_AMOUNT_ERROR,
    {11024, "Amount must be between 0 and Long.MAX_VALUE"}};
SdkError invalid_srcaddress_error = {INVALID_SOURCEADDRESS_ERROR,
                                     {11002, "Invalid sourceAddress"}};
SdkError invalid_dstaddress_error = {INVALID_DESTADDRESS_ERROR,
                                     {11003, "Invalid destAddress"}};
SdkError invalid_initbalance_error = {
    INVALID_INITBALANCE_ERROR,
    {11004, "InitBalance must be between 1 and Long.MAX_VALUE"}};
SdkError equal_srcdstaddress_error = {
    SOURCEADDRESS_EQUAL_DESTADDRESS_ERROR,
    {11005, "SourceAddress cannot be equal to destAddress"}};
SdkError invalid_address_error = {INVALID_ADDRESS_ERROR,
                                  {11006, "Invalid address"}};
SdkError connectnetwork_error = {CONNECTNETWORK_ERROR,
                                 {11007, "Failed to connect to the network"}};
SdkError no_metadatas_error = {
    NO_METADATAS_ERROR, {11010, "The account does not have this metadatas"}};
SdkError invalid_datakey_error = {
    INVALID_DATAKEY_ERROR,
    {11011, "The length of key must be between 1 and 1024"}};
SdkError invalid_datavalue_error = {
    INVALID_DATAVALUE_ERROR,
    {11012, "The length of value must be between 0 and 256000"}};
SdkError invalid_dataversion_error = {
    INVALID_DATAVERSION_ERROR,
    {11013, "The version must be equal to or greater than 0"}};
SdkError invalid_masterweight_error = {
    INVALID_MASTERWEIGHT_ERROR,
    {11015, "MasterWeight must be between 0 and = "
            "response.BifBaseResponse{Integer.MAX_VALUE // 2L + 1"}};
SdkError invalid_signeraddress_error = {INVALID_SIGNER_ADDRESS_ERROR,
                                        {11016, "Invalid signer address"}};
SdkError invalid_signerweight_error = {
    INVALID_SIGNER_WEIGHT_ERROR,
    {11017, "Signer weight must be between 0 and = "
            "response.BifBaseResponse{Integer.MAX_VALUE // 2L + 1)"}};
SdkError invalid_txthreshold_error = {
    INVALID_TX_THRESHOLD_ERROR,
    {11018, "TxThreshold must be between 0 and Long.MAX_VALUE"}};
SdkError invalid_typethreshold_error = {
    INVALID_TYPETHRESHOLD_TYPE_ERROR,
    {11019, "Type of TypeThreshold is invalid"}};
SdkError invalid_threshold_error = {
    INVALID_TYPE_THRESHOLD_ERROR,
    {11020, "TypeThreshold must be between 0 and Long.MAX_VALUE"}};
SdkError invalid_contracthash_error = {
    INVALID_CONTRACT_HASH_ERROR,
    {11025, "Invalid transaction hash to create contract"}};
SdkError invalid_gasamount_error = {
    INVALID_GAS_AMOUNT_ERROR,
    {11026, "bifAmount must be between 0 and Long.MAX_VALUE"}};
SdkError invalid_contractaddress_error = {INVALID_CONTRACTADDRESS_ERROR,
                                          {11037, "Invalid contract address"}};
SdkError invalid_notcontractaddr_error = {
    CONTRACTADDRESS_NOT_CONTRACTACCOUNT_ERROR,
    {11038, "contractAddress is not a contract account"}};
SdkError srcaddress_nocontracaddr_error = {
    SOURCEADDRESS_EQUAL_CONTRACTADDRESS_ERROR,
    {11040, "SourceAddress cannot be equal to contractAddress"}};
SdkError invalid_fromaddr_error = {INVALID_FROMADDRESS_ERROR,
                                   {11041, "Invalid fromAddress"}};
SdkError fromaddr_notdstaddr_error = {
    FROMADDRESS_EQUAL_DESTADDRESS_ERROR,
    {11042, "FromAddress cannot be equal to destAddress"}};
SdkError invalid__spender_error = {INVALID_SPENDER_ERROR,
                                   {11043, "Invalid spender"}};
SdkError payload_empty_error = {PAYLOAD_EMPTY_ERROR,
                                {11044, "Payload cannot be empty"}};
SdkError invalid_contracttype_error = {INVALID_CONTRACT_TYPE_ERROR,
                                       {11047, "Invalid contract type"}};
SdkError invalid_nonce_error = {
    INVALID_NONCE_ERROR, {11048, "Nonce must be between 1 and Long.MAX_VALUE"}};
SdkError invalid_gasprice_error = {
    INVALID_GASPRICE_ERROR,
    {11049, "GasPrice must be between 0 and Long.MAX_VALUE"}};
SdkError invalid_feelimit_error = {
    INVALID_FEELIMIT_ERROR,
    {11050, "FeeLimit must be between 0 and Long.MAX_VALUE"}};
SdkError operation_empty_error = {OPERATIONS_EMPTY_ERROR,
                                  {11051, "Operations cannot be empty"}};
SdkError invalid_ceilledgerseq_error = {
    INVALID_CEILLEDGERSEQ_ERROR,
    {11052, "CeilLedgerSeq must be equal to or greater than 0"}};
SdkError operations_one_error = {
    OPERATIONS_ONE_ERROR, {11053, "One of the operations cannot be resolved"}};
SdkError invalid_signaturenumber_error = {
    INVALID_SIGNATURENUMBER_ERROR,
    {11054, "SignagureNumber must be between 1 and Integer.MAX_VALUE"}};
SdkError invalid_hash_error = {INVALID_HASH_ERROR,
                               {11055, "Invalid transaction hash"}};
SdkError invalid_serialization_error = {INVALID_SERIALIZATION_ERROR,
                                        {11056, "Invalid serialization"}};
SdkError privatekey_empty_error = {PRIVATEKEY_NULL_ERROR,
                                   {11057, "PrivateKeys cannot be empty"}};
SdkError privatekey_one_error = {PRIVATEKEY_ONE_ERROR,
                                 {11058, "One of privateKeys is invalid"}};
SdkError signdata_empty_error = {SIGNDATA_NULL_ERROR,
                                 {11059, "SignData cannot be empty"}};
SdkError invalid_blocknumber_error = {
    INVALID_BLOCKNUMBER_ERROR, {11060, "BlockNumber must be bigger than 0"}};
SdkError publickey_empty_error = {PUBLICKEY_NULL_ERROR,
                                  {11061, "PublicKey cannot be empty"}};
SdkError url_empty_error = {URL_EMPTY_ERROR, {11062, "Url cannot be empty"}};
SdkError contractaddr_codeempty_error = {
    CONTRACTADDRESS_CODE_BOTH_NULL_ERROR,
    {11063, "ContractAddress and code cannot be empty at the same time"}};
SdkError invalid_opttype_error = {INVALID_OPTTYPE_ERROR,
                                  {11064, "OptType must be between 0 and 2"}};
SdkError get_allowance_error = {GET_ALLOWANCE_ERROR,
                                {11065, "Failed to get allowance"}};
SdkError signature_empty_error = {SIGNATURE_EMPTY_ERROR,
                                  {11067, "The signatures cannot be empty"}};
SdkError operation_type_error = {OPERATION_TYPE_ERROR,
                                 {11077, "Operation type cannot be empty"}};
SdkError connection_blockchain_error = {
    CONNECTN_BLOCKCHAIN_ERROR, {19999, "Failed to connect blockchain"}};
SdkError system_error = {SYSTEM_ERROR, {20000, "System error"}};
SdkError request_empty_error = {REQUEST_NULL_ERROR,
                                {12001, "Request parameter cannot be null"}};
SdkError invalid_contractbalance_error = {
    INVALID_CONTRACTBALANCE_ERROR,
    {12002, "ContractBalance must be between 1 and Long.MAX_VALUE"}};
SdkError invalid_pritxfrom_error = {
    INVALID_PRITX_FROM_ERROR, {12003, "Invalid Private Transaction Sender"}};
SdkError invalid_pritxpayload_error = {
    INVALID_PRITX_PAYLAOD_ERROR,
    {12004, "Invalid Private Transaction payload"}};
SdkError invalid_pritxlto_error = {
    INVALID_PRITX_TO_ERROR,
    {12005, "Invalid Private Transaction recipient list"}};
SdkError invalid_pritxhash_error = {
    INVALID_PRITX_HASH_ERROR, {12006, "Invalid Private Transaction Hash"}};
SdkError invalid_domainid_error = {
    INVALID_DOMAINID_ERROR,
    {12007, "Domainid must be equal to or greater than 0"}};
SdkError operations_length_error = {
    OPERATIONS_LENGTH_ERROR,
    {11068, "Operations length must be between 1 and 100"}};

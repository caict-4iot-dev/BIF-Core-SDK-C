# 1. BIF-Core-SDK-C使用说明

​		本节详细说明BIF-Core-SDK-C常用接口文档。星火链提供C语言版本的 SDK供开发者使用。

​        **github**代码库地址：https://github.com/caict-4iot-dev/BIF-Core-SDK-C

## 1.1 SDK概述

### 1.1.1 名词解析

+ 账户服务： 提供账户相关的有效性校验、创建与查询接口

+ 合约服务： 提供合约相关的有效性校验、创建与查询接口

+ 交易服务： 提供构建交易及交易查询接口

+ 区块服务： 提供区块的查询接口

+ 账户nonce值： 每个账户都维护一个序列号，用于用户提交交易时标识交易执行顺序的

### 1.1.2 请求参数与相应数据格式

+ **请求参数**

​		接口的请求参数的类名，是\[服务名][方法名]Request，例如: 账户服务下的getAccount接口的请求参数格式是BIFAccountGetInfoRequest。

​		请求参数的成员，是各个接口的入参的成员。例如：账户服务下的getAccount接口的入参成员是address，那么该接口的请求参数的完整结构如下：

```java
struct BifAccountGetInfoRequest {
	char address[128];
}
```

+ **响应数据**

​		接口的响应数据的结构体名字，是\[服务名][方法名]Response，例如：账户服务下的getNonce接口的响应数据格式是BIFAccountGetNonceResponse。

​		响应数据的成员，包括错误码、错误描述和返回结果。响应数据的成员如下：

```java
struct BifAccountResponses {
	BifBaseResponse baseResponse;
	char *value; 
}
```

1. baseResponse: 包含错误码和响应信息。错误码为0表示响应正常，其他错误码请查阅[错误码详情](# 1.8 错误码)。
2. value: 转发底层链返回的响应信息，格式为json串。



## 1.2 SDK使用方法

​		本节介绍SDK的使用流程。

​		首先需要初始化对应请求参数，然后调用相应服务接口，其中服务包括账户服务、合约服务、交易服务和区块服务。

### 1.2.1 生成公私钥地址等信息

+ **Ed25519算法生成**

```java
	//生成公私钥对及address等信息
    KeyPairEntity key_pair_entity;
    memset(&key_pair_entity, 0,sizeof(KeyPairEntity));

	int ret = get_bid_and_key_pair(&key_pair_entity);
	key_pair_entity.enc_address;
	key_pair_entity.enc_public_key;
	key_pair_entity.enc_private_key;
	key_pair_entity.raw_public_key;
	key_pair_entity.raw_private_key;
```

+ **SM2算法生成**

```java
	//生成公私钥对及address
    KeyPairEntity key_pair_entity;
    memset(&key_pair_entity, 0,sizeof(KeyPairEntity));

    int ret = get_bid_and_key_pair_by_sm2(&key_pair_entity);
	key_pair_entity.enc_address;
	key_pair_entity.enc_public_key;
	key_pair_entity.enc_private_key;
	key_pair_entity.raw_public_key;
	key_pair_entity.raw_private_key;
```

### 1.2.2 PrivateKeyManager使用



+ **生成对应类型的公私钥对函数接口**

```java
//根据指定类型生成对应private_key_manager
//定义初始化 
PrivateKeyManager *private_key_manager = (PrivateKeyManager*)malloc(sizeof(PrivateKeyManager));
memset(private_key_manager, 0,sizeof(PrivateKeyManager));

int ret = get_private_key_manager(ED25519, private_key_manager);
//根据星火私钥获取 private_key_manager
char *enc_private_key = "priSPKgVtTWUQuRPbjiE47s4QohxWc1svjFC6pbQyW4K3JPiae";
PrivateKeyManager *private_key_manager =(PrivateKeyManager*)malloc(sizeof(PrivateKeyManager));
memset(private_key_manager, 0,sizeof(PrivateKeyManager));
memcpy(private_key_manager, get_private_manager_by_enc_private(enc_private_key),sizeof(PrivateKeyManager)); 

//星火私钥
private_key_manager->enc_private_key
//星火address
private_key_manager->enc_address
//星火公钥
private_key_manager->enc_public_key
//原生私钥
private_key_manager->raw_private_key
//原生私钥长度
private_key_manager->raw_private_key_len
//原生公钥
private_key_manager->raw_public_key
//原生公钥长度
private_key_manager->raw_public_key_len
//类型
private_key_manager->type_key
```

+ **根据星火私钥获取星火公钥**

```c
char* enc_private_Key = "priSPKgVtTWUQuRPbjiE47s4QohxWc1svjFC6pbQyW4K3JPiae";
char enc_public_key[256] = {0};
    
strcpy(enc_public_key, get_enc_public_key(enc_private_Key));

```

+ **原生私钥转星火私钥**

```c
char enc_private_key[256] = {0};
strcpy(enc_private_key, get_enc_private_key(raw_private_key, raw_private_len, ED25519)); 

```

+ **原生公钥转星火公钥**

```c
char enc_public_key[256] = {0};
strcpy(enc_public_key, get_enc_public_key_by_raw_public(raw_public_key, raw_public_len, ED25519));

```

+ **签名**

```c
#
char* src = "hello";//待签名的源数据
char signature[1024] = {0}; //存放最后sign签名的数据
int sign_len = 0;//签名后数据长度
char *enc_private_key = "priSPKgVtTWUQuRPbjiE47s4QohxWc1svjFC6pbQyW4K3JPiae";

char *sign_temp = sign(enc_private_key, src, strlen(src), &sign_len);//strlen(src)代表待签名数据实际长度，当时二进制数据时此处应该输入真实长度，不能用strlen函数求，因为中间有\0会截断算不出真实长度
memcpy(signature, sign_temp, sign_len);
signature[sign_len] = '\0';

```

### 1.2.3 公钥相关函数使用

+ **获取账号地址**

```c
char enc_address[128] = {0};
char* enc_public_key = "B0656686FB2C33A6B67D8A853FC61BAB839DA1AEBC59757FAA1573EACDAF2D8CD326D6";
//get_enc_address函数第一个参数是星火公钥 第二个参数是chaincode 
strcpy(address, get_enc_address(enc_public_key, ""));
```



+ **账号地址校验**

```c
char* enc_address = "did:bid:efWNykMYgqX8iBTqDpoNN3Ja8xnSX1vE";

bool valid = is_address_valid(enc_address);
```



+ **验签** 

```c

char* src = "hello"; //待验签的源数据
char signature[1024] = {0};//签名sign数据
int signature_len = 0;//签名sign数据长度
char* enc_public_key = "B0656686FB2C33A6B67D8A853FC61BAB839DA1AEBC59757FAA1573EACDAF2D8CD326D6";
#签名后信息
char* sign = "633B12B028CF5D3A94599E0642FACFAB9953313AD96EDCA6B11D2ED0A5939D0AB9C0A3742E6C46AFD62637E8895824F4ABDD370DFC43B724D14017A3A046430F";//signature的hex 十六进制签名信息
hex_string_to_byte(sign, signature, &signature_len); //十六进制转char *字符数组信息
signature[out_len] = '\0';

 bool flag = false;
 flag = verify(src, signature, signature_len, enc_public_key);
 if(flag)
 {
 	printf("--verify successed\n");
 }
 else{
    printf("--verify failed\n");
 }


```

### 1.2.4 密钥存储器

+ **生成密钥存储器**

```c
generate_key_store(char* enc_private_key, char* password, uint64_t n, int p, int r, int version)
```

>  请求参数

| 参数            | 类型     | 描述                     |
| --------------- | -------- | ------------------------ |
| enc_private_key | char*    | 待存储的密钥，可为空串   |
| password        | char*    | 口令                     |
| n               | uint64_t | CPU消耗参数，必填且大于1 |
| p               | int      | 并行化参数，必填         |
| r               | int      | 内存消息参数，必填       |
| version         | int      | 版本号，必填             |

> 响应数据

| 参数     | 类型      | 描述                   |
| -------- | --------- | ---------------------- |
| keyStore | KEY_STORE | 存储密钥的存储器结构体 |

> 示例

```c
//私钥
char enc_private_key[128] = "priSPKepT8DV8wTAYiAU6LjUPQFqdzN9ndcVPMv9cgNeTBYQ6V";
//口令
char *password = "12334";
//版本
int version = (int) Math.pow(2, 16);
//generate_key_store
KEY_STORE *key_store_temp = generate_key_store(enc_private_key, password, version);

```

+ **解析密钥存储器**

```
decipher_key_store(password, key_store)
```

>  请求参数

| 参数      | 类型       | 描述             |
| --------- | ---------- | ---------------- |
| password  | char*      | 口令             |
| key_store | KEY_STORE* | 存储密钥的存储器 |

> 响应数据

| 参数            | 类型  | 描述               |
| --------------- | ----- | ------------------ |
| enc_private_key | char* | 解析出来的星火密钥 |

> 示例

```c
char password[64] = "12334";
KEY_STORE key_store；

strcpy(key_store.address, "did:bid:ef9VNKH9oTAfvdxgQmf5mNV41kQcPbKu");
strcpy(key_store.aesctr_iv, "BF357FE83B518634E62A37F2B2F12C17");
strcpy(key_store.cypher_text, "907E962812E8951FCFB799316F9744954FA9D5789E7161CC67BCBDF6F1511B6404DCF436BA54B408B8EFD2EB9A09AAF2FF25");
strcpy(key_store.scrypt_params.salt, "185501172118F577C01E16BA62673D5417F60A768ECFF9D82D0481266D38040D");
key_store.version = 65535;
key_store.scrypt_params.n = 16384;
key_store.scrypt_params.p = 1;
key_store.scrypt_params.r = 8;

char enc_private_key[256] = {0};
strcpy(enc_private_key, decipher_key_store(password, &key_store));
printf("decipher_key_store of private_key:%s\n", enc_private_key);

```

### 1.2.5 助记词

+ **生成助记词**

  ```c
  const char *mnemonic_generate(int strength)
  ```


> 请求参数

| 参数     | 类型 | 描述                                                         |
| -------- | ---- | ------------------------------------------------------------ |
| strength | int  | 要生成多少加密位的助记词，必须是32的倍数128-256位,目前只支持128位即生成对应12个助记词 |

> 响应数据

| 参数     | 类型         | 描述   |
| -------- | ------------ | ------ |
| mnemonic | const char * | 助记词 |

> 示例

```c
//generate mnemonic
const char *mnemo = mnemonic_generate(128);
printf("mnemonic: %s\n\n", mnemo);

```

+ **根据助记词生成私钥**

  ```c
  char* generate_private_keys_by_crypto(const char *mnemonic, const char *hd_path) //无KeyTypes参数接口，默认创建ED25519类型私钥
  char* generate_private_keys_by_crypto_type(const char *mnemonic, const char *hd_path, KeyTypes key_type)//创建指定ED25519或者SM2类型私钥，其他类型返回NULL
  ```

> 请求参数

| 参数     | 类型     | 描述                                                         |
| -------- | -------- | ------------------------------------------------------------ |
| mnemonic | char*    | 必填，助记词                                                 |
| hdPaths  | char*    | 必填，路径                                                   |
| KeyType  | KeyTypes | 选填，加密类型ED25519/SM2，generate_private_keys_by_crypto_type接口时此类型必填 |

> 响应数据

| 参数            | 类型  | 描述     |
| --------------- | ----- | -------- |
| enc_private_key | char* | 星火私钥 |

> 示例

```c

char *enc_private_key = (char*)malloc(256);
memset(enc_private_key, 0 , 256);
const char hd_path[32] = "m/44'/0/0'/0/0";
const char mnemonic[512] = "swift old dial that wave naive seminar lecture increase coyote scheme end";
   
strcpy(enc_private_key, generate_private_keys_by_crypto_type(mnemonic, hd_path, ED25519));
printf("enc_private_key:%s\n", enc_private_key);

```

### 1.2.6 SDS相关内存管理接口说明

​	sds类型是简单动态字符串的简称，类似c语言中原生的char *，其实底层就是typedef char *的写法，只是对内存处理接口做了封装处理，可以直接引入sds.h及sdscompat.h等相关sds开头的头文件既可使用，除了常规字符串，还支持其他图片等二进制安全(比如中间可能有\0)的数据.后续处理使用，可以自动扩容内存。

​	**1.sds声明定义用法**

​	在项目中包含sds相关头文件后直接sds a这种格式定义变量即可，和char *并无区别，使用前先初始化如；

​    sds a = sdsempty();此为定义初始化了sds类型的变量a，sdsempty()相当于malloc了初始长度0的内存，内容为“”

​    **2.sds相关接口说明**

​	 sds sdscpy(sds a，char* b)；类似标准库里的strcpy接口，将char*的b拷贝到sds的变量a中并返回最新的，最后自动末尾添加\0

​	 sds sdscat(sds a,char *b);类似标准库中的strcati接口功能，拼接两个字符串生成最新的，末尾自动添加\0

​	 sds sdsnew(char* b);将char* b的变量从以空结尾的C字符串开始创建新的sds字符串。

​	 size_t sdslen(sds a);类似标准库的strlen函数，计算sds的实际占用长度

​     void sdsfree(sds a);释放函数接口，专门释放sds类型的变量

​	其他更多接口可以详见对应sds.h头文件即可。

 **3.sdsfree与sdk_free区别**

​	sdfree接口是专门释放sds类型变量的接口，sdk_free是释放标准类型void *的接口。



## 1.3 账户服务接口列表

​		账户服务接口主要是账户相关的接口，目前有7个接口：

| 序号 | 接口                  | 说明                                  |
| ---- | --------------------- | ------------------------------------- |
| 1    | create_account        | 生成主链数字身份                      |
| 2    | get_account           | 该接口用于获取指定的账户信息          |
| 3    | get_nonce             | 该接口用于获取指定账户的nonce值       |
| 4    | get_account_balance   | 该接口用于获取指定账户的星火令余额    |
| 5    | set_metadatas         | 设置账户metadatas                     |
| 6    | get_account_metadatas | 该接口用于获取指定账户的metadatas信息 |
| 7    | set_privilege         | 设置用户权限                          |
| 8    | get_account_priv      | 接口用于获取指定账户的权限信息        |

### 1.3.1 create_account

> 接口说明

```
该接口用于生成主链数字身份，接口中的url变量为星火链url地址，必填，所有接口都需要
```

> 调用方法

```c
BifAccountResponse* create_account(BifCreateAccountRequest req, const char* url);
```

> 请求参数

| 参数            | 类型    | 描述                                                         |
| --------------- | ------- | ------------------------------------------------------------ |
| sender_address  | char*   | 必填，交易源账号，即交易的发起方                             |
| private_key     | char*   | 必填，交易源账户私钥                                         |
| ceil_ledger_seq | int64_t | 选填，区块高度限制, 默认设置0，如果大于0，则交易只有在该区块高度之前（包括该高度）才有效 |
| gas_price       | int64_t | 选填，打包费用 ，单位是星火萤（glowstone)，默认设置100       |
| fee_limit       | long    | 选填，交易花费的手续费，单位是星火萤(glowstone)，默认1000000L |
| domainId        | int     | 选填，指定域ID，默认主共识域id(0)，如果没有业务域的话必须设置默认的主共识域0，后面关于此domainid字段都是一样的规则 |
| dest_address    | char*   | 必填，目标账户地址                                           |
| init_balance    | int64_t | 必填，初始化星火令，单位星火萤，1 星火令 = 10^8 glowstone    |
| remarks         | char*   | 选填，用户自定义给交易的备注                                 |

> 响应字段数据

| 参数                                  | 类型                | 描述                                   |
| ------------------------------------- | ------------------- | -------------------------------------- |
| BifAccountResponse                    | BifAccountResponse* | 链响应的包含交易hash等字段的结构体指针 |
| BifAccountResponse->value             | char*               | 包含交易hash等信息的json串             |
| BifAccountResponse->baseResponse      | BifBaseResponse     | 发送链交易之前的异常错误码等信息结构体 |
| BifAccountResponse->baseResponse.code | int                 | 错误码                                 |
| BifAccountResponse->baseResponse.msg  | char*               | 错误信息                               |


> 异常错误码信息

| 异常                      | 错误码 | 描述                                             |
| ------------------------- | ------ | ------------------------------------------------ |
| INVALID_ADDRESS_ERROR     | 11006  | Invalid address                                  |
| REQUEST_NULL_ERROR        | 12001  | Request parameter cannot be null                 |
| PRIVATEKEY_NULL_ERROR     | 11057  | PrivateKeys cannot be empty                      |
| INVALID_DESTADDRESS_ERROR | 11003  | Invalid destAddress                              |
| INVALID_INITBALANCE_ERROR | 11004  | InitBalance must be between 1 and Long.MAX_VALUE |
| SYSTEM_ERROR              | 20000  | System error                                     |
| INVALID_DOMAINID_ERROR    | 12007  | Domainid must be equal to or greater than 0      |


> 示例

```c
    char bif_url[64] = "http://test.bifcore.bitfactory.cn";
    //创建账户
    BifAccountResponse *res_create_account;
    BifCreateAccountRequest req_create_account;
    memset(&req_create_account,0,sizeof(BifCreateAccountRequest));

    req_create_account.domainid = 0;  strcpy(req_create_account.private_key,"priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");
    strcpy(req_create_account.sender_address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
    strcpy(req_create_account.dest_address,"did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfT0");
    req_create_account.init_balance = 1000000;
    strcpy(req_create_account.remarks,"testremarks");

    res_create_account = create_account(req_create_account, bif_url);
    if(res_create_account->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_create_account->baseResponse.code,res_create_account->baseResponse.msg);
    else
        printf("%s\n", res_create_account->value);
  account_response_release(res_create_account); // 释放内存资源

```

> 返回示例的响应json数据

```c
{
   "results" : [
      {
         "error_code" : 0,
         "error_desc" : "",
         "hash" : "c018856c22553097117ae0de3e3406ef1d4f257933f3f5923a91e0c0a84bd77a"
      }
   ],
   "success_count" : 1
}
```



### 1.3.2 get_account

> 接口说明

   	该接口用于获取指定的账户信息。

> 调用方法

```c
BIFAccountGetInfoResponse get_account(BifAccountGetInfoRequest req, const char* url);
```

> 请求参数

| 参数    | 类型   | 描述                         |
| ------- | ------ | ---------------------------- |
| address | char* | 必填，待查询的区块链账户地址 |
| domainId| int | 选填，指定域ID，默认主共识域id(0) |
|  |  |  |

> 响应数据

| 参数                             | 类型                | 描述                                   |
| -------------------------------- | ------------------- | -------------------------------------- |
| BifAccountResponse               | BifAccountResponse* | 响应的结构体指针，包含所有数据         |
| BifAccountResponse->baseResponse | BifBaseResponse     | 包含错误码信息的结构体，详见错误码章节 |
| BifAccountResponse->value        | char*               | 包含账号地址，余额等字段的json信息     |

> 错误码

| 异常                  | 错误码 | 描述                             |
| --------------------- | ------ | -------------------------------- |
| INVALID_ADDRESS_ERROR | 11006  | Invalid address                  |
| REQUEST_NULL_ERROR    | 12001  | Request parameter cannot be null |
| CONNECTNETWORK_ERROR  | 11007  | Failed to connect to the network |
| SYSTEM_ERROR          | 20000  | System error                     |
| INVALID_DOMAINID_ERROR| 12007  | Domainid must be equal to or greater than 0 |

> 示例

```c
	// 初始化请求参数
    char bif_url[64] = "http://test.bifcore.bitfactory.cn";

    BifAccountGetInfoRequest req_account_base;
    BifAccountResponse *res_account_base;
    memset(&req_account_base, 0, sizeof(BifAccountGetInfoRequest));
    strcpy(req_account_base.address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
    //获取账户信息接口的函数
    res_account_base = get_account(req_account_base, bif_url);
	if(res_account_base->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_account_base->baseResponse.code,res_account_base->baseResponse.msg);
    else
        printf("%s\n", res_account_base->value);

    account_response_release(res_account_base); //释放内存资源

```

> 返回示例的响应json数据

```c
{
   "error_code" : 0,
   "result" : {
      "address" : "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe",
      "assets_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
      "balance" : 9223371985849985233,
      "metadatas_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
      "nonce" : 27,
      "priv" : {
         "master_weight" : 2,
         "signers" : [
            {
               "address" : "did:bid:efNiQPEGnhTPqaFatoF1p9wgr152P68F",
               "weight" : 2
            }
         ],
         "thresholds" : {
            "tx_threshold" : 2,
            "type_thresholds" : [
               {
                  "threshold" : 1,
                  "type" : 1
               },
               {
                  "threshold" : 2,
                  "type" : 7
               }
            ]
         }
      }
   }
}
```



### 1.3.3 get_nonce

> 接口说明

   	该接口用于获取指定账户的nonce值。

> 调用方法

```c
int get_nonce(BifAccountGetInfoRequest req, const char* url);
```

> 请求参数

| 参数    | 类型   | 描述                         |
| ------- | ------ | ---------------------------- |
| address | char* | 必填，待查询的区块链账户地址 |
| domainId| int | 选填，指定域ID，默认主共识域id(0) |

> 响应数据

| 参数                           | 类型                | 描述                   |
| ------------------------------ | ------------------- | ---------------------- |
| res_account_base               | BifAccountResponse* | 响应结构体指针         |
| res_account_base->baseResponse | BifBaseResponse     | 包含错误码信息的结构体 |
| res_account_base->value        | char*               | 包含nonce信息json串    |

> 错误码

| 参数                   | 类型  | 描述                                        |
| ---------------------- | ----- | ------------------------------------------- |
| INVALID_ADDRESS_ERROR  | 11006 | Invalid address                             |
| REQUEST_NULL_ERROR     | 12001 | Request parameter cannot be null            |
| CONNECTNETWORK_ERROR   | 11007 | Failed to connect to the network            |
| INVALID_DOMAINID_ERROR | 12007 | Domainid must be equal to or greater than 0 |

> 示例

```c
	// 初始化请求参数     
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
    BifAccountGetInfoRequest req_nonce;
	BifAccountResponse *res_account_base;
    memset(&req_nonce, 0, sizeof(req_nonce));
    req_nonce.domainid = 0;
    memset(req_nonce.address, 0 ,sizeof(req_nonce.address));
    strcpy(req_nonce.address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
    res_account_base = get_nonce(req_nonce, bif_url);
    if(res_account_base->baseResponse.code != 0)
        printf("code:%d,msg:%s\n\n",res_account_base->baseResponse.code,res_account_base->baseResponse.msg);
    else
        printf("%s\n\n", res_account_base->value);
  account_response_release(res_account_base); //释放内存资源

```

> 返回示例的响应json数据

```c
{"error_code": 0, "result": {"nonce": 40}}
```



### 1.3.4 get_account_balance

> 接口说明

  	该接口用于获取指定账户的余额

> 调用方法

```c
BIFAccountGetBalanceResponse get_account_balance(BifAccountGetInfoRequest req, const char* url);
```

> 请求参数

| 参数    | 类型   | 描述                         |
| ------- | ------ | ---------------------------- |
| address | char* | 必填，待查询的区块链账户地址 |
| domainId| int | 选填，指定域ID，默认主共识域id(0) |

> 响应数据

| 参数                             | 类型                | 描述                         |
| -------------------------------- | ------------------- | ---------------------------- |
| BifAccountResponse               | BifAccountResponse* | 返回的响应结构体指针         |
| BifAccountResponse->baseResponse | BifBaseResponse     | 包含错误码信息的结构体       |
| BifAccountResponse->value        | char*               | 包含余额等字段的链响应json串 |
| BifAccountResponse->balance      | long                | 余额字段                     |
|                                  |                     |                              |



> 错误码

| 异常                  | 错误码 | 描述                             |
| --------------------- | ------ | -------------------------------- |
| INVALID_ADDRESS_ERROR | 11006  | Invalid address                  |
| REQUEST_NULL_ERROR    | 12001  | Request parameter cannot be null |
| CONNECTNETWORK_ERROR  | 11007  | Failed to connect to the network |
| SYSTEM_ERROR          | 20000  | System error                     |
| INVALID_DOMAINID_ERROR| 12007  | Domainid must be equal to or greater than 0 |

> 示例

```c
	// 初始化请求参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
 	//获取账户balance
	BifAccountGetInfoRequest req_account_base;
    BifAccountResponse *res_account_base;
    memset(&req_account_base, 0, sizeof(BifAccountGetInfoRequest));
    strcpy(req_account_base.address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
    res_account_base = get_account_balance(req_account_base, bif_url);
    if(res_account_base->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_account_base->baseResponse.code,res_account_base->baseResponse.msg);
    else
        printf("%s,balance:%ld\n", res_account_base->value,res_account_base->balance);
    account_response_release(res_account_base); //释放内存资源

```

> 返回示例的响应json数据

```c
{"error_code": 0, "result": {"balance": 9223371964739196702}}
```



### 1.3.5 set_metadatas

> 接口说明

   	该接口用于修改账户的metadatas信息。

> 调用方法

```java
BIFAccountSetMetadatasResponse set_metadatas(BifAccountSetMetadatasRequest req, const char* url);
```

> 请求参数

| 参数            | 类型    | 描述                                                         |
| --------------- | ------- | ------------------------------------------------------------ |
| sender_address  | char*   | 必填，交易源账号，即交易的发起方                             |
| private_key     | char*   | 必填，交易源账户私钥                                         |
| ceil_ledger_seq | int64_t | 选填，区块高度限制, 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效 |
| remarks         | char*   | 选填，用户自定义给交易的备注                                 |
| key             | char*   | 必填，OperationsData结构体中变量，metadatas的key，长度限制[1, 1024] |
| value           | char*   | 必填，OperationsData结构体中变量，metadatas的内容，长度限制[0, 256000] |
| version         | int64_t | 选填，OperationsData结构体中变量，metadatas的版本            |
| delete_flag     | bool    | 选填，OperationsData结构体中变量，是否删除remarks            |
| gas_price       | int64_t | 选填，打包费用 ，单位是星火萤(glowstone)，默认100            |
| fee_limit       | int64_t | 选填，交易花费的手续费，单位是星火萤(glowstone)，默认1000000 |
| domainId        | int     | 选填，指定域ID，默认主共识域id(0)                            |

> 响应数据

| 参数                             | 类型                | 描述                              |
| -------------------------------- | ------------------- | --------------------------------- |
| BifAccountResponse               | BifAccountResponse* | 返回的响应结构体指针,包含所有字段 |
| BifAccountResponse->baseResponse | BifBaseResponse     | 包含错误码等信息结构体            |
| value                            | char *              | 包含hash的json串                  |


> 错误码

| 异常                    | 错误码 | 描述                                             |
| ----------------------- | ------ | ------------------------------------------------ |
| INVALID_ADDRESS_ERROR   | 11006  | Invalid address                                  |
| REQUEST_NULL_ERROR      | 12001  | Request parameter cannot be null                 |
| PRIVATEKEY_NULL_ERROR   | 11057  | PrivateKeys cannot be empty                      |
| INVALID_DATAKEY_ERROR   | 11011  | The length of key must be between 1 and 1024     |
| INVALID_DATAVALUE_ERROR | 11012  | The length of value must be between 0 and 256000 |
| INVALID_DOMAINID_ERROR  | 12007  | Domainid must be equal to or greater than 0      |


> 示例

```c
	// 初始化请求参数
    char bif_url[64] = "http://test.bifcore.bitfactory.cn";

    //设置账户metadatas
  	BifAccountResponse *res_set_account_metasatas;
  	BifAccountSetMetadatasRequest req_set_account_metasatas;

  	char *key = "zzl04";
  	char *value = "hello1";
  	req_set_account_metasatas.operations_array[0].value =
      	(char *)sdk_malloc(strlen(value) + 1);

  	req_set_account_metasatas.operations_num = 1; // operations_array个数
  	memset(&req_set_account_metasatas.private_key, 0,
         sizeof(req_set_account_metasatas.private_key));
  	memset(&req_set_account_metasatas.sender_address, 0,
         sizeof(req_set_account_metasatas.private_key));
  	memset(&req_set_account_metasatas.remarks, 0,
         sizeof(req_set_account_metasatas.remarks));

  	req_set_account_metasatas.domainid = 0;
  	req_set_account_metasatas.fee_limit = 0;
  	req_set_account_metasatas.gas_price = 0;
  	strcpy(req_set_account_metasatas.private_key,
         "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");
  	strcpy(req_set_account_metasatas.sender_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");

  	strcpy(req_set_account_metasatas.operations_array[0].Key, key);
  	strcpy(req_set_account_metasatas.operations_array[0].value, value);
  	req_set_account_metasatas.operations_array[0].delete_flag = false;

  	res_set_account_metasatas = 	set_metadatas(req_set_account_metasatas, bif_url);
  	if (res_set_account_metasatas->baseResponse.code != 0)
    	printf("code:%d,msg:%s\n", res_set_account_metasatas->baseResponse.code,res_set_account_metasatas->baseResponse.msg);
  	else
    	printf("%s\n", res_set_account_metasatas->value);
  	account_response_release(res_set_account_metasatas); // 释放内存资源
  	account_request_meta_release(
      &req_set_account_metasatas); // 释放request中metadata内存资源

  	return 0;
```

> 返回示例的响应json数据

```c
{
   "results" : [
      {
         "error_code" : 0,
         "error_desc" : "",
         "hash" : "e2b6b2f6e03d2f557b71b5145ebf1e1b32d3fe80cbccc4e40018cedb9628ee17"
      }
   ],
   "success_count" : 1
}
```

### 1.3.6 get_account_metadatas

> 接口说明

   	该接口用于获取指定账户的metadatas信息。

> 调用方法

```c
BIFAccountGetMetadatasResponse get_account_metadatas(BifAccountGetMetadatasRequest req, const char* url);
```

> 请求参数

| 参数     | 类型  | 描述                                                         |
| -------- | ----- | ------------------------------------------------------------ |
| address  | char* | 必填，待查询的账户地址                                       |
| key      | char* | 选填，metadatas关键字，长度限制[1, 1024]，有值为精确查找，无值为全部查找 |
| domainId | int   | 选填，指定域ID，默认主共识域id(0)                            |

> 响应数据

| 参数                             | 类型                | 描述                                   |
| -------------------------------- | ------------------- | -------------------------------------- |
| BifAccountResponse               | BifAccountResponse* | 响应的结构体指针，包含所有响应信息字段 |
| BifAccountResponse->baseResponse | BifBaseResponse     | 包含错误码信息的基础响应结构体         |
| value                            | char*               | 链响应的json串                         |


> 错误码

| 异常                   | 错误码 | 描述                                         |
| ---------------------- | ------ | -------------------------------------------- |
| INVALID_ADDRESS_ERROR  | 11006  | Invalid address                              |
| REQUEST_NULL_ERROR     | 12001  | Request parameter cannot be null             |
| CONNECTNETWORK_ERROR   | 11007  | Failed to connect to the network             |
| INVALID_DATAKEY_ERROR  | 11011  | The length of key must be between 1 and 1024 |
| INVALID_DOMAINID_ERROR | 12007  | Domainid must be equal to or greater than 0  |


> 示例

```java
	// 初始化请求参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
   //查询指定地址的metadatas接口
    BifAccountGetMetadatasRequest req_metadata;
    BifAccountResponse *res_metadata;
    memset(&req_metadata, 0,sizeof(req_metadata));
    req_metadata.domainid = 0;
    strcpy(req_metadata.address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");

    res_metadata = get_account_metadatas(req_metadata, bif_url);
    if(res_metadata->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_metadata->baseResponse.code,res_metadata->baseResponse.msg);
    else
        printf("get_account_metadatas: %s\n", res_metadata->value);
    account_response_release(res_metadata); //释放内存资源

```

> 返回示例的响应json数据

```c
{"error_code": 0, "result": {"metadatas": [{"key": "ed25519-3", "value": "ed25519value!-3", "version": 1}, {"key": "zzl", "value": "hello", "version": 2}, {"key": "zzl02", "value": "hello", "version": 1}, {"key": "zzl03", "value": "hello", "version": 1}, {"key": "zzl04", "value": "hello1", "version": 1}]}}
```

### 1.3.7 set_privilege

> 接口说明

   	该接口用于设置权限。

> 调用方法

```c
BIFAccountSetPrivilegeResponse set_privilege(BifAccountSetPrivilegeRequest req, const char* url);
```

> 请求参数

| 参数                     | 类型               | 描述                                                         |
| ------------------------ | ------------------ | ------------------------------------------------------------ |
| sender_address           | char*              | 必填，交易源账号，即交易的发起方                             |
| private_key              | char*              | 必填，交易源账户私钥                                         |
| ceil_ledger_seq          | long               | 选填，区块高度限制, 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效 |
| remarks                  | char*              | 选填，用户自定义给交易的备注                                 |
| signers                  | BifSigner[]        | 选填，签名者权重列表                                         |
| signers.address          | char*              | 签名者区块链账户地址                                         |
| signers.weight           | int64_t            | 为签名者设置权重值                                           |
| tx_threshold             | char*              | 选填，交易门限数量                                           |
| typeThresholds           | BifTypeThreshold[] | 选填，指定类型交易门限                                       |
| typeThresholds.type      | int                | 操作类型，必须大于0                                          |
| typeThresholds.threshold | int64_t            | 门限值，大小限制[0, Long.MAX_VALUE]                          |
| master_weight            | char*              | 选填，权重                                                   |
| gas_price                | int64_t            | 选填，打包费用 单位是星火萤(glowstone)，默认100              |
| fee_limit                | int64_t            | 选填，交易花费的手续费，单位是星火萤(glowstone)，默认1000000 |
| domainId                 | int                | 选填，指定域ID，默认主共识域id(0)                            |

> 响应数据

| 参数               | 类型                | 描述                   |
| ------------------ | ------------------- | ---------------------- |
| BifAccountResponse | BifAccountResponse* | 返回的链响应结构体指针 |
| baseResponse       | BifBaseResponse     | 包含错误码信息的响应   |
| value              | char*               | 返回的包含hash的json串 |


> 错误码

| 异常                   | 错误码 | 描述                                        |
| ---------------------- | ------ | ------------------------------------------- |
| INVALID_ADDRESS_ERROR  | 11006  | Invalid address                             |
| REQUEST_NULL_ERROR     | 12001  | Request parameter cannot be null            |
| PRIVATEKEY_NULL_ERROR  | 11057  | PrivateKeys cannot be empty                 |
| CONNECTNETWORK_ERROR   | 11007  | Failed to connect to the network            |
| INVALID_DOMAINID_ERROR | 12007  | Domainid must be equal to or greater than 0 |


> 示例

```c
     //初始化参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
     //设置账户metadatas
    BifAccountResponse *res_set_privilege;
    BifAccountSetPrivilegeRequest req_set_privilege;
    memset(&req_set_privilege, 0 ,sizeof(BifAccountSetPrivilegeRequest));
    char *address = "did:bid:efNiQPEGnhTPqaFatoF1p9wgr152P68F";

    req_set_privilege.signers_num = 1;
    strcpy(req_set_privilege.signers[0].address, address);

    strcpy(req_set_privilege.master_weight, "2");
    strcpy(req_set_privilege.private_key, "priSPKdgaD3SnJ94nJNijiHsmrsWn8yXXeroCwDJp3q5WU4hxY");
    strcpy(req_set_privilege.sender_address, "did:bid:efjijAvhn6hVCnEueAm52rp9N6hwS2bf");
    req_set_privilege.type_threshold_num = 2;
    req_set_privilege.typeThresholds[0].type = 1;
    req_set_privilege.typeThresholds[0].threshold = 1;
    req_set_privilege.typeThresholds[1].type = 7;
    req_set_privilege.typeThresholds[1].threshold = 2;
    strcpy(req_set_privilege.tx_threshold, "2");
    
    res_set_privilege = set_privilege(req_set_privilege, bif_url);
    if(res_set_privilege->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_set_privilege->baseResponse.code,res_set_privilege->baseResponse.msg);
    else
        printf("%s\n", res_set_privilege->value);
    account_response_release(res_set_privilege); // 释放内存资源

```

> 返回示例的响应json数据

```c
{
   "results" : [
      {
         "error_code" : 0,
         "error_desc" : "",
         "hash" : "aebff8afad824bada041b7340bc8c98003c26cb1dc380b965dfabbfb011bec93"
      }
   ],
   "success_count" : 1
}
```

### 1.3.8 get_account_priv

> 接口说明

   	该接口用于获取指定账户的权限信息。

> 调用方法

```c
BifAccountResponse get_account_priv(BifAccountGetInfoRequest req, const char* url);
```

> 请求参数

| 参数     | 类型  | 描述                              |
| -------- | ----- | --------------------------------- |
| address  | char* | 必填，待查询的区块链账户地址      |
| domainId | int   | 选填，指定域ID，默认主共识域id(0) |

> 响应数据

| 参数               | 类型                | 描述                   |
| ------------------ | ------------------- | ---------------------- |
| BifAccountResponse | BifAccountResponse* | 返回的链响应结构体指针 |
| baseResponse       | BifBaseResponse     | 包含错误码信息的响应   |
| value              | char*               | 返回的包含hash的json串 |


> 错误码

| 异常                   | 错误码 | 描述                                        |
| ---------------------- | ------ | ------------------------------------------- |
| INVALID_ADDRESS_ERROR  | 11006  | Invalid address                             |
| REQUEST_NULL_ERROR     | 12001  | Request parameter cannot be null            |
| PRIVATEKEY_NULL_ERROR  | 11057  | PrivateKeys cannot be empty                 |
| CONNECTNETWORK_ERROR   | 11007  | Failed to connect to the network            |
| INVALID_DOMAINID_ERROR | 12007  | Domainid must be equal to or greater than 0 |


> 示例

```c
     //初始化参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
     //获取指定账户权限接口
    BifAccountResponse *res_account_base;
    BifAccountGetInfoRequest req_account_base;
    memset(&req_account_base, 0, sizeof(BifAccountGetInfoRequest));
    strcpy(req_account_base.address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
    res_account_base = get_account_priv(req_account_base, bif_url);
    if(res_account_base->baseResponse.code != 0)
        printf("code:%d,msg:%s\n\n",res_account_base->baseResponse.code,res_account_base->baseResponse.msg);
    else
        printf("%s\n\n", res_account_base->value);
    account_response_release(res_account_base); //释放内存资源

```

> 返回示例的响应json数据

```c
{"error_code": 0, "result": {"address": "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe", "priv": {"master_weight": 2, "thresholds": {"tx_threshold": 2}}}}
```

## 

## 1.4 合约服务接口列表

​		合约服务接口主要是合约相关的接口，目前有6个接口：

| 序号 | 接口                   | 说明                               |
| ---- | ---------------------- | ---------------------------------- |
| 1    | check_contract_address | 该接口用于检测合约账户的有效性     |
| 2    | contract_create        | 创建合约                           |
| 3    | get_contract_info      | 该接口用于查询合约代码             |
| 4    | get_contract_address   | 该接口用于根据交易Hash查询合约地址 |
| 5    | contract_query         | 该接口用于调试合约代码             |
| 6    | contract_invoke        | 合约调用                           |
| 7    | contract_batch_invoke  | 批量合约调用                       |

### 1.4.1 check_contract_address

> 接口说明

   	该接口用于检测合约账户的有效性。

> 调用方法

```java
BifContractCheckValidResponse *check_contract_address(BifContractCheckValidRequest req, const char* url);
```

> 请求参数

| 参数            | 类型   | 描述                 |
| --------------- | ------ | -------------------- |
| contract_address | char* | 待检测的合约账户地址 |
| domainId        | int | 选填，指定域ID，默认主共识域id(0)       |

> 响应数据

| 参数     | 类型 | 描述                  |
| -------- | ---- | --------------------- |
| is_valid | bool | 是否有效 0无效，1有效 |

> 错误码

| 异常                          | 错误码 | 描述                             |
| ----------------------------- | ------ | -------------------------------- |
| INVALID_CONTRACTADDRESS_ERROR | 11037  | Invalid contract address         |
| REQUEST_NULL_ERROR            | 12001  | Request parameter cannot be null |
| INVALID_DOMAINID_ERROR| 12007  | Domainid must be equal to or greater than 0  |

> 示例

```c
   // 初始化请求参数
   char bif_url[64] = "http://test.bifcore.bitfactory.cn";
   //合约模块-根据address domainid获取合约地址是否可用接口
   BifContractCheckValidRequest req_check_contract_addr;
   BifContractCheckValidResponse *res_contract_check_addr;
   	memset(&req_check_contract_addr,0,sizeof(BifContractCheckValidRequest));
   strcpy(req_check_contract_addr.contract_address, "did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv");
   res_contract_check_addr = check_contract_address(req_check_contract_addr, bif_url);

    if(res_contract_check_addr->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_contract_check_addr->baseResponse.code,res_contract_check_addr->baseResponse.msg);
    else
        printf("check_contract_address:%s\n\n", res_contract_check_addr->value);
    contract_valid_response_release(res_contract_check_addr);

```

> 返回示例的响应json数据

```c
{"error_code": 0, "error_desc": "Success", "result": {"is_valid": true}}
```



### 1.4.2 contract_create

> 接口说明

   	该接口用于创建合约。

> 调用方法

```java
BifContractGetInfoResponse *contract_create(BifContractCreateRequest req, const char* url);
```

> 请求参数

| 参数          | 类型    | 描述                                                         |
| ------------- | ------- | ------------------------------------------------------------ |
| sender_address | char* | 必填，交易源账号，即交易的发起方                             |
| gas_price | int64_t | 选填，打包费用 ，单位是星火萤(glowstone)，默认100 |
| fee_limit | int64_t | 选填，交易花费的手续费，单位是星火萤(glowstone)，默认1000000 |
| private_key | char* | 必填，交易源账户私钥                                         |
| ceil_ledger_seq | long   | 选填，区块高度限制, 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效 |
| remarks       | char* | 选填，用户自定义给交易的备注                                 |
| init_balance | long | 必填，给合约账户的初始化星火令，单位是星火萤(glowstone)，1 星火令 = 10^8 glowstone, 大小限制[1, Long.MAX_VALUE] |
| payload       | sds | 必填，对应语种的合约代码                                     |
| init_input | sds | 选填，合约代码中init方法的入参 |
| type | int | 选填，合约的类型，默认是0 , 0: javascript，1 :evm |
| domainId      | int | 选填，指定域ID，默认主共识域id(0)       |

> 响应数据

| 参数                       | 类型                        | 描述                       |
| -------------------------- | --------------------------- | -------------------------- |
| BifContractGetInfoResponse | BifContractGetInfoResponse* | 链响应结构体指针           |
| baseResponse               | BifBaseResponse             | 包含错误码信息的基础结构体 |
| value                      | char*                       | 包含交易hash的json串       |


> 错误码

| 异常                      | 错误码 | 描述                                             |
| ------------------------- | ------ | ------------------------------------------------ |
| INVALID_ADDRESS_ERROR     | 11006  | Invalid address                                  |
| REQUEST_NULL_ERROR        | 12001  | Request parameter cannot be null                 |
| PRIVATEKEY_NULL_ERROR     | 11057  | PrivateKeys cannot be empty                      |
| INVALID_INITBALANCE_ERROR | 11004  | InitBalance must be between 1 and Long.MAX_VALUE |
| PAYLOAD_EMPTY_ERROR       | 11044  | Payload cannot be empty                          |
| INVALID_FEELIMIT_ERROR    | 11050  | FeeLimit must be between 0 and Long.MAX_VALUE    |
| SYSTEM_ERROR              | 20000  | System error                                     |
| INVALID_DOMAINID_ERROR    | 12007  | Domainid must be equal to or greater than 0      |


> 示例

```c
	// 初始化请求参数
    char bif_url[64] = "http://test.bifcore.bitfactory.cn";
    //创建合约example
     BifContractGetInfoResponse *res_create_contract;
  	BifContractCreateRequest req_create_contract;
  	memset(&req_create_contract, 0, sizeof(BifContractCreateRequest));
  	char payload[] =
      	"\"use strict\";function queryBanance1(address)\r\n{return \" 		test query "
      "private contract\";}\r\nfunction create1(input)\r\n{let key = "
      "\"private_tx_\"+input.id;let value = \"set private id "
      "\"+input.id;Chain.store(key,value);}\r\nfunction "
      "init(input)\r\n{return;}\r\nfunction "
      "main(input)\r\n{return;}\r\nfunction query1(input)\r\n{let key = "
      "\"private_tx_\"+input.id;let data = Chain.load(key);return data;}";
  	input_sds_initialize(&req_create_contract.payload,
                       payload); // 初始化赋值请求中sds类型变量接口
  	req_create_contract.gas_price = 10;
  	req_create_contract.fee_limit = 100000000;

  	strcpy(req_create_contract.private_key,
         "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");
  	strcpy(req_create_contract.sender_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  	req_create_contract.contract_type = 0;
  	req_create_contract.init_balance = 100000000;

  	res_create_contract = contract_create(req_create_contract, bif_url);
  	if (res_create_contract->baseResponse.code != 0)
    	printf("code:%d,msg:%s\n", res_create_contract->baseResponse.code,res_create_contract->baseResponse.msg);
  	else
    	printf("%s\n", res_create_contract->value);
  	contract_info_response_release(res_create_contract);
  	contract_sds_request_release(req_create_contract.payload);
```

> 返回示例的响应json数据

```c
{
   "results" : [
      {
         "error_code" : 0,
         "error_desc" : "",
         "hash" : "6340e52dc916a6c0c1dd03cd51de7a87e40af3496931b11db544dcc3aaa09904"
      }
   ],
   "success_count" : 1
}
```

### 1.4.3 get_contract_info

> 接口说明

   	该接口用于查询合约代码。

> 调用方法

```c
BifContractCheckValidResponse *get_contract_info(BifContractCheckValidRequest req, const char* url);
```

> 请求参数

| 参数            | 类型   | 描述                 |
| --------------- | ------ | -------------------- |
| contract_address | char* | 必填，待查询的合约账户地址 |
| domainId        | int | 选填，指定域ID，默认主共识域id(0)       |

> 响应数据

| 参数                                        | 类型                           | 描述                     |
| ------------------------------------------- | ------------------------------ | ------------------------ |
| BifContractCheckValidResponse               | BifContractCheckValidResponse* | 返回的合约信息结构体指针 |
| BifContractCheckValidResponse->baseResponse | BifBaseResponse                | 包含错误码信息的结构体   |
| BifContractCheckValidResponse->value        | char*                          | 包含所有合约信息的json串 |

> 错误码

| 异常                                      | 错误码 | 描述                                        |
| ----------------------------------------- | ------ | ------------------------------------------- |
| INVALID_CONTRACTADDRESS_ERROR             | 11037  | Invalid contract address                    |
| CONTRACTADDRESS_NOT_CONTRACTACCOUNT_ERROR | 11038  | contractAddress is not a contract account   |
| REQUEST_NULL_ERROR                        | 12001  | Request parameter cannot be null            |
| INVALID_DOMAINID_ERROR                    | 12007  | Domainid must be equal to or greater than 0 |
| CONNECTNETWORK_ERROR                      | 11007  | Failed to connect to the network            |

> 示例

```c
	// 初始化请求参数
    char bif_url[64] = "http://test.bifcore.bitfactory.cn";
	BifContractCheckValidRequest req_contract_info;
    BifContractCheckValidResponse *res_contract_info;
    memset(&req_contract_info,0,sizeof(BifContractCheckValidRequest));
    req_contract_info.domainid = 0;
    strcpy(req_contract_info.contract_address, "did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv");
    res_contract_info = get_contract_info(req_contract_info, bif_url);

    if(res_contract_info->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_contract_info->baseResponse.code,res_contract_info->baseResponse.msg);
    else
        printf("get_contract_info:%s\n", res_contract_info->value);
    contract_valid_response_release(res_contract_info);

```

> 返回示例的响应json数据

```json
{
   "error_code" : 0,
   "result" : {
      "address" : "did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv",
      "assets_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
      "balance" : 100000,
      "contract" : {
         "payload" : "\"use strict\";function queryBanance(address)\r\n{return \" test query private contract\";}\r\nfunction create(input)\r\n{let key = \"private_tx_\"+input.id;let value = \"set private id \"+input.id;Chain.store(key,value);}\r\nfunction init(input)\r\n{return;}\r\nfunction main(input)\r\n{return;}\r\nfunction query(input)\r\n{let key = \"private_tx_\"+input.id;let data = Chain.load(key);return data;}"
      },
      "metadatas_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
      "priv" : {
         "thresholds" : {
            "tx_threshold" : 1
         }
      }
   }
}
```

### 1.4.4 get_contract_address

> 接口说明

```
该接口用于根据交易Hash查询合约地址。
```

> 调用方法

```java
BIFContractGetAddressResponse get_contract_address(BIFContractGetAddressRequest);
```

> 请求参数

| 参数 | 类型   | 描述               |
| ---- | ------ | ------------------ |
| hash | char* | 必填，创建合约交易的hash |
| domainId | int | 选填，指定域ID，默认主共识域id(0)       |

> 响应数据

| 参数              | 类型                        | 描述                     |
| ----------------- | --------------------------- | ------------------------ |
| res               | BifContractGetInfoResponse* | 返回的合约信息结构体指针 |
| res->baseResponse | BifBaseResponse             | 包含错误码信息的结构体   |
| res->value        | char*                       | 包含合约地址信息的json串 |

> 错误码

| 异常                 | 错误码 | 描述                             |
| -------------------- | ------ | -------------------------------- |
| INVALID_HASH_ERROR   | 11055  | Invalid transaction hash         |
| CONNECTNETWORK_ERROR | 11007  | Failed to connect to the network |
| REQUEST_NULL_ERROR   | 12001  | Request parameter cannot be null |
| INVALID_DOMAINID_ERROR | 12007  | Domainid must be equal to or greater than 0      |

> 示例

```c
	// 初始化请求参数
 	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
	BifContractGetAddressRequest req_contract_addr;
    BifContractGetInfoResponse *res_contract_addr;
    memset(&req_contract_addr, 0 ,sizeof(BifContractGetAddressRequest));
    //hash根据实际节点交易生成的值即可
    char hash_test[] = "2f25e770b7ede0966a920cc91503d5354be0b87e2cb3d237869449cd4290101f";
    strcpy(req_contract_addr.hash, hash_test);
    res_contract_addr = get_contract_address(req_contract_addr, bif_url);

    if(res_contract_addr->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_contract_addr->baseResponse.code,res_contract_addr->baseResponse.msg);
    else
        printf("get_contract_address:%s\n", res_contract_addr->value);
    contract_info_response_release(res_contract_addr);
```

> 返回示例的响应json数据

```json
[{"contract_address":"did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv","operation_index":0,"vm_type":0}]
```

### 1.4.5 contract_query

> 接口说明

   	该接口用于调用合约查询接口。

> 调用方法

```c
BifContractGetInfoResponse *contract_query(BifContractCallRequest req, const char* url);
```

> 请求参数

| 参数             | 类型    | 描述                                                         |
| ---------------- | ------- | ------------------------------------------------------------ |
| source_address   | char*   | 选填，合约触发账户地址                                       |
| contract_address | char*   | 必填，合约账户地址                                           |
| input            | char*   | 选填，合约入参                                               |
| gas_price        | int64_t | 选填，打包费用 ，单位是星火萤(glowstone)，默认100L           |
| fee_limit        | int64_t | 选填，交易花费的手续费，单位是星火萤(glowstone)，默认1000000L |
| domainId         | int     | 选填，指定域ID，默认主共识域id(0)                            |


> 响应数据

| 参数                                     | 类型                        | 描述                             |
| ---------------------------------------- | --------------------------- | -------------------------------- |
| BifContractGetInfoResponse               | BifContractGetInfoResponse* | 响应结构体指针                   |
| BifContractGetInfoResponse->baseResponse | BifBaseResponse             | 包含错误码信息结构体             |
| value                                    | char*                       | 包含query_rets等合约信息的json串 |

> 错误码

| 异常                                      | 错误码 | 描述                                             |
| ----------------------------------------- | ------ | ------------------------------------------------ |
| INVALID_SOURCEADDRESS_ERROR               | 11002  | Invalid sourceAddress                            |
| INVALID_CONTRACTADDRESS_ERROR             | 11037  | Invalid contract address                         |
| SOURCEADDRESS_EQUAL_CONTRACTADDRESS_ERROR | 11040  | SourceAddress cannot be equal to contractAddress |
| REQUEST_NULL_ERROR                        | 12001  | Request parameter cannot be null                 |
| SYSTEM_ERROR                              | 20000  | System error                                     |
| INVALID_DOMAINID_ERROR                    | 12007  | Domainid must be equal to or greater than 0      |

> 示例

```c
	// 初始化请求参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
    BifContractGetInfoResponse *res_contract_query;
  	BifContractCallRequest req_contract_query;
  	memset(&req_contract_query, 0, sizeof(BifContractCallRequest));
  	char init_input[] =
      "{\"function\":\"queryBanance(string)\",\"args\":\"did:bid:"
      "efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv\",\"return\":\"returns(string)\"}";

  	input_sds_initialize(&req_contract_query.input,
                       init_input); // 初始化赋值给sds类型的变量接口
  	strcpy(req_contract_query.contract_address,
         "did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv");
  	strcpy(req_contract_query.source_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");

  	res_contract_query = contract_query(req_contract_query, bif_url);
  	if (res_contract_query->baseResponse.code != 0)
    	printf("code:%d,msg:%s\n", res_contract_query->baseResponse.code,res_contract_query->baseResponse.msg);
  	else
    	printf("%s\n", res_contract_query->value);
  	contract_info_response_release(res_contract_query);
  	// 释放请求体中sds类型的内存变量
  	contract_sds_request_release(req_contract_query.input);

```

> 返回示例的响应json数据

```json
{
   "error_code" : 0,
   "error_desc" : "",
   "result" : {
      "logs" : {
         "0-did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv" : null
      },
      "query_rets" : [
         {
            "result" : {
               "type" : "bool",
               "value" : false
            }
         }
      ],
      "stat" : {
         "apply_time" : 131048,
         "memory_usage" : 1816328,
         "stack_usage" : 16,
         "step" : 107
      },
      "txs" : null
   }
}
```

### 1.4.6 contract_invoke

> 接口说明

   	该接口用于合约调用。

> 调用方法

```c
BifContractGetInfoResponse *contract_invoke(BifContractInvokeRequest req, const char* url);
```

> 请求参数

| 参数             | 类型    | 描述                                                         |
| ---------------- | ------- | ------------------------------------------------------------ |
| sender_address   | char*   | 必填，交易源账号，即交易的发起方                             |
| gas_price        | int64_t | 选填，打包费用，单位是星火萤(glowstone)，默认100             |
| fee_limit        | int64_t | 选填，交易花费的手续费，单位是星火萤(glowstone)，默认1000000 |
| private_key      | char*   | 必填，交易源账户私钥                                         |
| ceil_ledger_seq  | int64_t | 选填，区块高度限制, 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效 |
| remarks          | char*   | 选填，用户自定义给交易的备注                                 |
| contract_address | char*   | 必填，合约账户地址                                           |
| amount           | int64_t | 必填，转账金额                                               |
| input            | sds     | 选填，待触发的合约的main()入参                               |
| domainId         | int     | 选填，指定域ID，默认主共识域id(0)                            |

> 响应数据

| 参数                                     | 类型                        | 描述                   |
| ---------------------------------------- | --------------------------- | ---------------------- |
| BifContractGetInfoResponse               | BifContractGetInfoResponse* | 响应结构体指针         |
| BifContractGetInfoResponse->baseResponse | BifBaseResponse             | 包含错误码信息结构体   |
| BifContractGetInfoResponse->value        | char*                       | 包含链响应字段的json串 |


> 错误码

| 异常                          | 错误码 | 描述                                          |
| ----------------------------- | ------ | --------------------------------------------- |
| INVALID_ADDRESS_ERROR         | 11006  | Invalid address                               |
| REQUEST_NULL_ERROR            | 12001  | Request parameter cannot be null              |
| PRIVATEKEY_NULL_ERROR         | 11057  | PrivateKeys cannot be empty                   |
| INVALID_CONTRACTADDRESS_ERROR | 11037  | Invalid contract address                      |
| INVALID_AMOUNT_ERROR          | 11024  | Amount must be between 0 and Long.MAX_VALUE   |
| INVALID_FEELIMIT_ERROR        | 11050  | FeeLimit must be between 0 and Long.MAX_VALUE |
| REQUEST_NULL_ERROR            | 12001  | Request parameter cannot be null              |
| INVALID_GASPRICE_ERROR        | 11049  | GasPrice must be between 0 and Long.MAX_VALUE |
| INVALID_DOMAINID_ERROR        | 12007  | Domainid must be equal to or greater than 0   |


> 示例

```c
	// 初始化请求参数
    char bif_url[64] = "http://test.bifcore.bitfactory.cn";
    BifContractGetInfoResponse *res_contract_invoke;
  	BifContractInvokeRequest req_contract_invoke;
  	memset(&req_contract_invoke, 0, sizeof(BifContractInvokeRequest));
  	char init_input[] =
      "{\"function\":\"queryBanance(string)\",\"args\":\"did:bid:"
      "efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv\",\"return\":\"returns(string)\"}";
  	input_sds_initialize(&req_contract_invoke.input,
                       init_input); // 初始化赋值给sds类型的变量接口
  	// 根据实际部署节点的合约地址等测试信息
  	strcpy(req_contract_invoke.contract_address,
         "did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv");
  	strcpy(req_contract_invoke.sender_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  	strcpy(req_contract_invoke.private_key,
         "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");
  	strcpy(req_contract_invoke.remarks, "test1234");
  	req_contract_invoke.amount = 0;

  	res_contract_invoke = contract_invoke(req_contract_invoke, bif_url);
  	if (res_contract_invoke->baseResponse.code != 0)
    	printf("code:%d,msg:%s\n", res_contract_invoke->baseResponse.code,
   res_contract_invoke->baseResponse.msg);
  	else
    	printf("%s\n", res_contract_invoke->value);
  	contract_info_response_release(res_contract_invoke);
  	// 释放请求体中sds类型的内存变量
  	contract_sds_request_release(req_contract_invoke.input);
```

> 返回示例的响应json数据

```json
{
   "results" : [
      {
         "error_code" : 0,
         "error_desc" : "",
         "hash" : "42a1295005b503ba0b4bb077d9566aa962527ba9c0ec502c0cbc2e8467a148c3"
      }
   ],
   "success_count" : 1
}
```

### 1.4.7 contract_batch_invoke

> 接口说明

   	该接口用于批量合约调用。

> 调用方法

```c
BifContractGetInfoResponse *contract_batch_invoke(BifBatchContractInvokeRequest req, const char* url);
```

> 请求参数

| 参数                                  | 类型             | 描述                                                         |
| ------------------------------------- | ---------------- | ------------------------------------------------------------ |
| sender_address                        | char*            | 必填，交易源账号，即交易的发起方                             |
| gas_price                             | int64_t          | 选填，打包费用， 单位是星火萤(glowstone)，默认100            |
| fee_limit                             | int64_t          | 选填，交易花费的手续费，单位是星火萤(glowstone)，默认1000000 |
| private_key                           | char*            | 必填，交易源账户私钥                                         |
| ceil_ledger_seq                       | int64_t          | 选填，区块高度限制, 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效 |
| remarks                               | char*            | 选填，用户自定义给交易的备注                                 |
| domainId                              | int              | 选填，指定域ID，默认主共识域id(0)                            |
| operation_batch_data                  | OperationBatch[] | 必填，合约调用集合                                           |
| operation_batch_num                   | int              | 必填，批量OperationBatch结构体个数（1,100],超过100会返回错误信息 |
| operation_batch_data.contract_address | char*            | 必填，合约账户地址                                           |
| operation_batch_data.amount           | int64_t          | 必填，转账金额                                               |
| operation_batch_data.input            | sds              | 选填，合约入参                                               |



> 响应数据

| 参数                                     | 类型                        | 描述                     |
| ---------------------------------------- | --------------------------- | ------------------------ |
| BifContractGetInfoResponse               | BifContractGetInfoResponse* | 响应结构体指针           |
| BifContractGetInfoResponse->baseResponse | BifBaseResponse             | 包含错误码信息的结构体   |
| BifContractGetInfoResponse->value        | char*                       | 链返回的包含hash的json串 |


> 错误码

| 异常                          | 错误码 | 描述                                          |
| ----------------------------- | ------ | --------------------------------------------- |
| INVALID_ADDRESS_ERROR         | 11006  | Invalid address                               |
| REQUEST_NULL_ERROR            | 12001  | Request parameter cannot be null              |
| PRIVATEKEY_NULL_ERROR         | 11057  | PrivateKeys cannot be empty                   |
| INVALID_CONTRACTADDRESS_ERROR | 11037  | Invalid contract address                      |
| INVALID_AMOUNT_ERROR          | 11024  | Amount must be between 0 and Long.MAX_VALUE   |
| INVALID_FEELIMIT_ERROR        | 11050  | FeeLimit must be between 0 and Long.MAX_VALUE |
| SYSTEM_ERROR                  | 20000  | System error                                  |


> 示例

```c
	// 初始化参数
    char bif_url[64] = "http://test.bifcore.bitfactory.cn";
      BifContractGetInfoResponse *res_batch_invoke;
  	BifBatchContractInvokeRequest req_batch_invoke;
  	memset(&req_batch_invoke, 0, sizeof(BifBatchContractInvokeRequest));
  	char init_input[] =
      "{\"function\":\"queryBanance(string)\",\"args\":\"did:bid:"
      "efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv\",\"return\":\"returns(string)\"}";
  	char init_input2[] =
      "{\"function\":\"queryBanance(string)\",\"args\":\"did:bid:"
      "ef2CENizhXm2VJYmHV1a8HULb2Xg32QcU\",\"return\":\"returns(string)\"}";

  	input_sds_initialize(&req_batch_invoke.operation_batch_data[0].input,
                       init_input); // 初始化赋值请求中sds类型变量值接口
  	input_sds_initialize(&req_batch_invoke.operation_batch_data[1].input,
                       init_input);

  	strcpy(req_batch_invoke.operation_batch_data[0].contract_address,
         "did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv");
  	strcpy(req_batch_invoke.operation_batch_data[1].contract_address,
         "did:bid:ef2CENizhXm2VJYmHV1a8HULb2Xg32QcU");
  	req_batch_invoke.operation_batch_data[0].amount = 0;
  	req_batch_invoke.operation_batch_data[1].amount = 0;
  	req_batch_invoke.operation_batch_num = 2; // operation_batch_data结构体数量

  	strcpy(req_batch_invoke.sender_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  	strcpy(req_batch_invoke.private_key,
         "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");
  	strcpy(req_batch_invoke.remarks, "0123456789abcdef");

  	res_batch_invoke = contract_batch_invoke(req_batch_invoke, bif_url);
  	if (res_batch_invoke->baseResponse.code != 0)
    	printf("code:%d,msg:%s\n", res_batch_invoke->baseResponse.code,
           res_batch_invoke->baseResponse.msg);
  	else
    	printf("%s\n", res_batch_invoke->value);
  	// sdk接口使用完，最后要调用释放内存函数
  	contract_info_response_release(res_batch_invoke);
  	// 释放请求体中sds类型的内存变量
  	contract_sds_request_release(req_batch_invoke.operation_batch_data[0].input);
  	// 释放请求体中sds类型的内存变量
  	contract_sds_request_release(req_batch_invoke.operation_batch_data[1].input);
```

> 返回示例的响应json数据

```json
{
   "results" : [
      {
         "error_code" : 0,
         "error_desc" : "",
         "hash" : "7e77fd04ffd7b64cb8dd09518a98418b617559a1fcc58d6777d8ab38d5055e51"
      }
   ],
   "success_count" : 1
}
```

## 1.5 交易服务接口列表

​		交易服务接口主要是交易相关的接口，目前有4个接口：

| 序号 | 接口                 | 说明                               |
| ---- | -------------------- | ---------------------------------- |
| 1    | gas_send             | 交易                               |
| 2    | get_transaction_info | 该接口用于实现根据交易hash查询交易 |
| 3    | evaluate_fee         | 该接口实现交易的费用评估           |
| 4    | bif_submit           | 提交交易                           |
| 5    | get_tx_cache_size    | 交易池中交易条数                   |
| 6    | evaluate_batch_fee   | 该接口为批量费用评估接口           |
| 7    | get_tx_cache_data    | 交易池中交易数据                   |
| 8    | parse_blob           | 用于blob数据解析                   |

### 1.5.1 gas_send

> 接口说明

   	该接口用于发起交易。

> 调用方法

```java
BifTransactionSubmitResponse *gas_send(BifTransactionGasSendRequest req, const char* url);
```

> 请求参数

| 参数            | 类型    | 描述                                                         |
| --------------- | ------- | ------------------------------------------------------------ |
| sender_address  | char*   | 必填，交易源账号，即交易的发起方                             |
| private_key     | char*   | 必填，交易源账户私钥                                         |
| ceil_ledger_seq | int64_t | 选填，区块高度限制, 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效 |
| remarks         | char*   | 选填，用户自定义给交易的备注                                 |
| dest_address    | char*   | 必填，目的地址                                               |
| amount          | int64_t | 必填，转账金额                                               |
| gas_price       | long    | 选填，打包费用，单位是星火萤(glowstone)，默认100             |
| fee_limit       | long    | 选填，交易花费的手续费，单位是星火萤(glowstone)，默认1000000 |
| domainId        | int     | 选填，指定域ID，默认主共识域id(0)                            |

> 响应数据

| 参数              | 类型                          | 描述                 |
| ----------------- | ----------------------------- | -------------------- |
| res               | BifTransactionSubmitResponse* | 响应结构体指针       |
| res->baseResponse | BifBaseResponse               | 包含错误码信息结构体 |
| res->value        | char*                         | 包含交易信息的json串 |


> 错误码

| 异常                      | 错误码 | 描述                                           |
| ------------------------- | ------ | ---------------------------------------------- |
| INVALID_ADDRESS_ERROR     | 11006  | Invalid address                                |
| REQUEST_NULL_ERROR        | 12001  | Request parameter cannot be null               |
| PRIVATEKEY_NULL_ERROR     | 11057  | PrivateKeys cannot be empty                    |
| INVALID_DESTADDRESS_ERROR | 11003  | Invalid destAddress                            |
| INVALID_GAS_AMOUNT_ERROR  | 11026  | BIFAmount must be between 0 and Long.MAX_VALUE |
| SYSTEM_ERROR              | 20000  | System error                                   |
| INVALID_DOMAINID_ERROR    | 12007  | Domainid must be equal to or greater than 0    |


> 示例

```c
	// 初始化请求参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
    BifTransactionGasSendRequest req_gas_send;
    BifTransactionSubmitResponse *res_gas_send;
    memset(&req_gas_send, 0, sizeof(BifTransactionGasSendRequest));

    req_gas_send.amount = 10;
    strcpy(req_gas_send.dest_address, "did:bid:zf32dF6p2NA1Dzw6ySQThL2v9W3Dmbje");
    strcpy(req_gas_send.sender_address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
    strcpy(req_gas_send.private_key, "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");

    res_gas_send = gas_send(req_gas_send, bif_url);
    if(res_gas_send->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_gas_send->baseResponse.code,res_gas_send->baseResponse.msg);
    else
        printf("%s\n", res_gas_send->value);
    transaction_submit_response_release(res_gas_send);

```

> 返回示例的响应json数据

```json
{
   "results" : [
      {
         "error_code" : 0,
         "error_desc" : "",
         "hash" : "8ff4ddb77e6018cb8232786df8c76260c4456e97ceb94e66fadd8df9213033e6"
      }
   ],
   "success_count" : 1
}
```



### 1.5.2 get_transaction_info

> 接口说明

   	该接口用于实现根据交易hash查询交易。

> 调用方法

```java
BifTransactionGetInfoResponse *get_transaction_info(BifTransactionGetInfoRequest req, const char* url);
```

> 请求参数

| 参数 | 类型   | 描述     |
| ---- | ------ | -------- |
| hash | char* | 必填，交易hash |
| domainId | int | 选填，指定域ID，默认主共识域id(0)       |

> 响应数据

| 参数                                        | 类型                           | 描述                   |
| ------------------------------------------- | ------------------------------ | ---------------------- |
| BifTransactionGetInfoResponse               | BifTransactionGetInfoResponse* | 响应结构体指针         |
| BifTransactionGetInfoResponse->baseResponse | BifBaseResponse                | 包含错误码信息结构体   |
| BifTransactionGetInfoResponse->value        | char*                          | 包含交易等信息的json串 |

> 错误码

| 异常                 | 错误码 | 描述                             |
| -------------------- | ------ | -------------------------------- |
| INVALID_HASH_ERROR   | 11055  | Invalid transaction hash         |
| REQUEST_NULL_ERROR   | 12001  | Request parameter cannot be null |
| CONNECTNETWORK_ERROR | 11007  | Failed to connect to the network |
| INVALID_DOMAINID_ERROR | 12007  | Domainid must be equal to or greater than 0    |

> 示例

```c
	// 初始化请求参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
	BifTransactionGetInfoRequest req_transaction_get_info;
   BifTransactionGetInfoResponse *res_transaction_get_info;
   memset(&req_transaction_get_info, 0, sizeof(BifTransactionGetInfoRequest));
   req_transaction_get_info.domainid = 0;
   char hash_data[] = "2f25e770b7ede0966a920cc91503d5354be0b87e2cb3d237869449cd4290101f";
   strcpy(req_transaction_get_info.hash, hash_data);

   res_transaction_get_info = get_transaction_info(req_transaction_get_info, bif_url);
   if(res_transaction_get_info->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_transaction_get_info->baseResponse.code,res_transaction_get_info->baseResponse.msg);
    else
        printf("%s\n", res_transaction_get_info->value);
    transaction_info_response_release(res_transaction_get_info);

```

> 返回示例的响应json数据

```json
{"error_code":0,"result":{"total_count":1,"transactions":[{"actual_fee":1000613,"close_time":1670397906728940,"error_code":0,"error_desc":"[{\"contract_address\":\"did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv\",\"operation_index\":0,\"vm_type\":0}]","hash":"2f25e770b7ede0966a920cc91503d5354be0b87e2cb3d237869449cd4290101f","ledger_seq":10154,"signatures":[{"public_key":"b0656681fe6bbb5ef40fa464b6fb8335da40c6814be2a1fed750228deda2ac2d496e6e","sign_data":"923ab072c6032e33e2a953d28ef038a55884a35914c8856db3d04e5b44c75258b107cc4e4971886a5aec2b3651793cee6317636c21ecfb5b0c90fe235c67980d"}],"transaction":{"fee_limit":1000000000,"gas_price":1,"nonce":7,"operations":[{"create_account":{"contract":{"payload":"\"use strict\";function queryBanance(address)\r\n{return \" test query private contract\";}\r\nfunction create(input)\r\n{let key = \"private_tx_\"+input.id;let value = \"set private id \"+input.id;Chain.store(key,value);}\r\nfunction init(input)\r\n{return;}\r\nfunction main(input)\r\n{return;}\r\nfunction query(input)\r\n{let key = \"private_tx_\"+input.id;let data = Chain.load(key);return data;}"},"init_balance":100000,"init_input":"[]","metadatas":[{"key":"test","value":"value"}],"priv":{"thresholds":{"tx_threshold":1}}},"type":1}],"source_address":"did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe"},"tx_size":613}]}}
```

### 1.5.3 evaluate_fee

> 接口说明

   	该接口实现交易的费用评估，目前支持合约创建，合约调用及转账交易类型费用评估。

> 调用方法

```java
BifTransactionGetInfoResponse *evaluate_fee(BifEvaluateFeeRequest req, const char* url);
```

> 请求参数

| 参数                      | 类型                       | 描述                                                         |
| ------------------------- | -------------------------- | ------------------------------------------------------------ |
| signature_number          | int                        | 选填，待签名者的数量，默认是1，大小限制[1, Integer.MAX_VALUE] |
| remarks                   | char*                      | 选填，用户自定义给交易的备注，16进制格式                     |
| sender_address            | char*                      | 必填，交易源账号，即交易的发起方                             |
| private_key               | char*                      | 必填，交易源账户私钥                                         |
| call_operation            | BifCallOperation           | 选填，如果是合约调用时必填                                   |
| create_contract_operation | BifContractCreateOperation | 选填，合约创建时为必填                                       |
| pay_coin_operation        | BifPayCoinOperation        | 选填, 转账时为必填                                           |
| gas_price                 | int64_t                    | 选填，打包费用，单位是星火萤(glowstone)，默认100             |
| fee_limit                 | int64_t                    | 选填，交易花费的手续费，单位是星火萤(glowstone)，默认1000000 |
| domainId                  | int                        | 选填，指定域ID，默认主共识域id(0)                            |

> 响应数据

| 参数                                        | 类型                            | 描述                 |
| ------------------------------------------- | ------------------------------- | -------------------- |
| BifTransactionGetInfoResponse               | BifTransactionGetInfoResponse * | 响应结构体指针       |
| BifTransactionGetInfoResponse->baseResponse | BifBaseResponse                 | 包括错误码信息结构体 |
| BifTransactionGetInfoResponse->value        | char*                           | 响应的json串         |

> 错误码

| 异常                          | 错误码 | 描述                                                    |
| ----------------------------- | ------ | ------------------------------------------------------- |
| INVALID_SOURCEADDRESS_ERROR   | 11002  | Invalid sourceAddress                                   |
| OPERATIONS_EMPTY_ERROR        | 11051  | Operations cannot be empty                              |
| OPERATIONS_ONE_ERROR          | 11053  | One of the operations cannot be resolved                |
| INVALID_SIGNATURENUMBER_ERROR | 11054  | SignagureNumber must be between 1 and Integer.MAX_VALUE |
| REQUEST_NULL_ERROR            | 12001  | Request parameter cannot be null                        |
| CONNECTNETWORK_ERROR          | 11007  | Failed to connect to the network                        |
| INVALID_DOMAINID_ERROR        | 12007  | Domainid must be equal to or greater than 0             |

> 示例

```c
    //初始化参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
	BifEvaluateFeeRequest req_evaluate;
    BifTransactionGetInfoResponse *res_evaluate;
    memset(&req_evaluate, 0,sizeof(BifEvaluateFeeRequest));

    req_evaluate.call_operation.amount = 10;
    strcpy(req_evaluate.call_operation.dest_address, "did:bid:ef2CENizhXm2VJYmHV1a8HULb2Xg32QcU");
    strcpy(req_evaluate.sender_address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
    strcpy(req_evaluate.remarks, "0123456789abcdef");
    strcpy(req_evaluate.private_key, "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");

    res_evaluate = evaluate_fee(req_evaluate, bif_url);
    if(res_evaluate->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_evaluate->baseResponse.code,res_evaluate->baseResponse.msg);
    else
        printf("%s\n", res_evaluate->value);
    transaction_info_response_release(res_evaluate);
```

> 返回示例的响应json数据

```json
{
   "error_code" : 0,
   "error_desc" : "",
   "result" : {
      "hash" : "3b0746d7d3d76a394986f8bb25e5edd575b36c745bdd613f74e9fad09208af97",
      "logs" : null,
      "query_rets" : null,
      "stat" : {
         "apply_time" : 0,
         "memory_usage" : 0,
         "stack_usage" : 0,
         "step" : 0
      },
      "txs" : [
         {
            "actual_fee" : 40600,
            "gas" : 406,
            "transaction_env" : {
               "transaction" : {
                  "fee_limit" : 40600,
                  "gas_price" : 100,
                  "nonce" : 37,
                  "operations" : [
                     {
                        "pay_coin" : {
                           "amount" : 10,
                           "dest_address" : "ef2CENizhXm2VJYmHV1a8HULb2Xg32QcU"
                        },
                        "type" : 6
                     }
                  ],
                  "source_address" : "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe"
               }
            }
         }
      ]
   }
}
```

### 1.5.4 bif_submit

> 接口说明

   	该接口用于交易提交。

> 调用方法

```java
BifTransactionSubmitResponse *bif_submit(BifTransactionSubmitRequest req, const char* url);
```

> 请求参数

| 参数          | 类型  | 描述                   |
| ------------- | ----- | ---------------------- |
| serialization | char* | 必填，交易blob序列化值 |
| sign_data     | char* | 必填，签名数据         |
| public_key    | char* | 必填，签名者星火公钥   |

> 响应数据

| 参数 | 类型  | 描述     |
| ---- | ----- | -------- |
| hash | char* | 交易hash |

> 错误码

| 异常                        | 错误码 | 描述                             |
| --------------------------- | ------ | -------------------------------- |
| INVALID_SERIALIZATION_ERROR | 11056  | Invalid serialization            |
| SIGNATURE_EMPTY_ERROR       | 11067  | The signatures cannot be empty   |
| SIGNDATA_NULL_ERROR         | 11059  | SignData cannot be empty         |
| PUBLICKEY_NULL_ERROR        | 11061  | PublicKey cannot be empty        |
| REQUEST_NULL_ERROR          | 12001  | Request parameter cannot be null |
| SYSTEM_ERROR                | 20000  | System error                     |

> 示例

```c
  	// 初始化参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
    BifTransactionSubmitRequest req_submit;
    BifTransactionSubmitResponse *res_submit;
    memset(&req_submit, 0, sizeof(req_submit));
    
    char public_key[] = "b0656681fe6bbb5ef40fa464b6fb8335da40c6814be2a1fed750228deda2ac2d496e6e";
    char serializa[] = "0a296469643a6269643a6566324175414a69643164423232726b334d3676423663556331454e6e7066456510022234080752300a286469643a6269643a65664e69515045476e68545071614661746f463170397767723135325036384610081a027b7d2a080123456789abcdef30c0843d3801";
    char sign_data[] = "00d337a3bbd669bb8c3fbe96dd1bc0a7f9f15d888da3e065e9fa006954452a709373eec2add701881f4fb67addd31630b1f6fadbf029125c350e95b0df752401";
    strcpy(req_submit.public_key, public_key);
	req_submit.serialization = (char *)malloc(strlen(serializa) + 1);
  	memset(req_submit.serialization, 0, strlen(serializa) + 1);
    strcpy(req_submit.serialization, serializa);
    strcpy(req_submit.sign_data, sign_data);

    res_submit = bif_submit(req_submit, bif_url);
    if(res_submit->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_submit->baseResponse.code,res_submit->baseResponse.msg);
    else
        printf("bif_submit res:%s\n", res_submit->value);
    transaction_submit_response_release(res_submit);
  	sdk_free(req_submit.serialization);

```

> 返回示例的响应json数据

```json
{
   "results" : [
      {
         "error_code" : 0,
         "error_desc" : "",
         "hash" : "c536aa2f0ae6d1413596da34a8bd02590fc139b09b3c5ddfba96fddfca0c8381"
      }
   ],
   "success_count" : 1
}
```

### 1.5.5 get_tx_cache_size

> 接口说明

   	该接口用于获取交易池中交易条数。

> 调用方法

```java
BifTransactionGetTxCacheSizeResponse *get_tx_cache_size(const char* url);
```

> 响应数据

| 参数                                 | 类型                                  | 描述                   |
| ------------------------------------ | ------------------------------------- | ---------------------- |
| BifTransactionGetTxCacheSizeResponse | BifTransactionGetTxCacheSizeResponse* | 响应结构体指针         |
| baseResponse                         | BifBaseResponse                       | 包含错误码信息的结构体 |
| value                                | char*                                 | 包含queue_size的json串 |

> 错误码

| 异常                 | 错误码 | 描述                             |
| -------------------- | ------ | -------------------------------- |
| CONNECTNETWORK_ERROR | 11007  | Failed to connect to the network |
| SYSTEM_ERROR         | 20000  | System error                     |

> 示例

```c
   char bif_url[64] = "http://test.bifcore.bitfactory.cn";
   BifTransactionGetTxCacheSizeResponse *res_get_tx_cache_size;
   int domainid = 0;
   res_get_tx_cache_size = get_tx_cache_size(domainid, bif_url);

   if(res_get_tx_cache_size->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_get_tx_cache_size->baseResponse.code,res_get_tx_cache_size->baseResponse.msg);
    else
        printf("%s\n\n", res_get_tx_cache_size->value);
    transaction_cachesize_response_release(res_get_tx_cache_size); // 释放内存

```

> 返回示例的响应json数据

```json
{"error_code": 0, "error_desc": "Success", "result": {"queue_size": 0}}

```

### 1.5.6 evaluate_batch_fee

> 接口说明

   	该接口为批量费用评估接口。

> 调用方法

```java
BifTransactionGetInfoResponse *evaluate_batch_fee(BifEvaluateFeeBatchRequest req, const char* url);
```

> 请求参数

| 参数                                       | 类型                       | 描述                                                         |
| ------------------------------------------ | -------------------------- | ------------------------------------------------------------ |
| signature_number                           | int                        | 选填，待签名者的数量，默认是1，大小限制[1, Integer.MAX_VALUE] |
| remarks                                    | char*                      | 选填，用户自定义给交易的备注                                 |
| sender_address                             | char*                      | 必填，交易源账号地址                                         |
| private_key                                | char*                      | 必填，交易源账号星火私钥                                     |
| operation_datas                            | OperationData[]            | 必填，待提交的操作，不能为空且元素个数大于1                  |
| operation_num                              | int                        | 必填，operation_datas结构体数量（1,100],超过100会返回错误信息 |
| operation_datas.call_operation             | BifCallOperation           | 选填，如果是合约调用则必填                                   |
| operation_datas.BifContractCreateOperation | BifContractCreateOperation | 选填，合约创建时则必填                                       |
| operation_datas.pay_coin_operation         | BifPayCoinOperation        | 选填，转账时则必填                                           |
| gas_price                                  | int64_t                    | 必填，打包费用 ，单位是星火萤(glowstone)，默认100            |
| fee_limit                                  | int64_t                    | 选填，交易花费的手续费，单位是星火萤(glowstone)，默认1000000 |
| domainId                                   | int                        | 选填，指定域ID，默认主共识域id(0)                            |



> 响应数据

| 参数              | 类型                           | 描述                   |
| ----------------- | ------------------------------ | ---------------------- |
| res               | BifTransactionGetInfoResponse* | 响应结构体指针         |
| res->baseResponse | BifBaseResponse                | 包含错误码信息的结构体 |
| res->value        | char*                          | 包含评估交易集的json串 |

> 错误码

| 异常                          | 错误码 | 描述                                                    |
| ----------------------------- | ------ | ------------------------------------------------------- |
| INVALID_SOURCEADDRESS_ERROR   | 11002  | Invalid sourceAddress                                   |
| OPERATIONS_EMPTY_ERROR        | 11051  | Operations cannot be empty                              |
| OPERATIONS_ONE_ERROR          | 11053  | One of the operations cannot be resolved                |
| INVALID_SIGNATURENUMBER_ERROR | 11054  | SignagureNumber must be between 1 and Integer.MAX_VALUE |
| REQUEST_NULL_ERROR            | 12001  | Request parameter cannot be null                        |
| INVALID_DOMAINID_ERROR        | 12007  | Domainid must be equal to or greater than 0             |

> 示例

```c
    // 初始化参数
    char bif_url[64] = "http://test.bifcore.bitfactory.cn";
    BifEvaluateFeeBatchRequest req_evaluate;
    BifTransactionGetInfoResponse *res_evaluate;
    memset(&req_evaluate, 0,sizeof(BifEvaluateFeeBatchRequest));

    req_evaluate.operation_datas[0].call_operation.amount = 10;
    req_evaluate.operation_datas[1].call_operation.amount = 12;
    strcpy(req_evaluate.operation_datas[0].call_operation.dest_address, "did:bid:zf6LBRqPHfXjg46JqkCTqGb8QM9GTFB78");
    strcpy(req_evaluate.operation_datas[1].call_operation.dest_address, "did:bid:ef2CENizhXm2VJYmHV1a8HULb2Xg32QcU");
    req_evaluate.operation_num = 2;
    strcpy(req_evaluate.sender_address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
    strcpy(req_evaluate.remarks, "0123456789abcdef");
    strcpy(req_evaluate.private_key, "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");

    res_evaluate = evaluate_batch_fee(req_evaluate, bif_url);
    if(res_evaluate->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_evaluate->baseResponse.code,res_evaluate->baseResponse.msg);
    else
        printf("%s\n", res_evaluate->value);
    transaction_info_response_release(res_evaluate);

```

> 返回示例的响应json数据

```json
{
   "error_code" : 0,
   "error_desc" : "",
   "result" : {
      "hash" : "f058ab2bb9e34ca690422eed355f5f6878fd32d6aab399e6884c4378ac54d801",
      "logs" : null,
      "query_rets" : null,
      "stat" : {
         "apply_time" : 0,
         "memory_usage" : 0,
         "stack_usage" : 0,
         "step" : 0
      },
      "txs" : [
         {
            "actual_fee" : 48400,
            "gas" : 484,
            "transaction_env" : {
               "transaction" : {
                  "fee_limit" : 48400,
                  "gas_price" : 100,
                  "metadata" : "30313233343536373839616263646566",
                  "nonce" : 39,
                  "operations" : [
                     {
                        "pay_coin" : {
                           "amount" : 10,
                           "dest_address" : "did:bid:zf6LBRqPHfXjg46JqkCTqGb8QM9GTFB78"
                        },
                        "type" : 6
                     },
                     {
                        "pay_coin" : {
                           "amount" : 12,
                           "dest_address" : "did:bid:ef2CENizhXm2VJYmHV1a8HULb2Xg32QcU"
                        },
                        "type" : 6
                     }
                  ],
                  "source_address" : "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe"
               }
            }
         }
      ]
   }
}

```



### 1.5.7 get_tx_cache_data

> 接口说明

   	该接口用于获取交易池中交易数据。

> 调用方法

```c
BifTransactionGetInfoResponse *get_tx_cache_data(BifTransactionGetInfoRequest req, const char* url);
```

> 请求参数

| 参数     | 类型  | 描述                              |
| -------- | ----- | --------------------------------- |
| hash     | char* | 选填，交易hash                    |
| domainId | int   | 选填，指定域ID，默认主共识域id(0) |

> 响应数据

| 参数                                        | 类型                           | 描述                 |
| ------------------------------------------- | ------------------------------ | -------------------- |
| BifTransactionGetInfoResponse               | BifTransactionGetInfoResponse* | 响应结构体指针       |
| BifTransactionGetInfoResponse->baseResponse | BifBaseResponse                | 包含错误码信息结构体 |
| BifTransactionGetInfoResponse->value        | char*                          | 包含对应交易的json串 |

> 错误码

| 异常                   | 错误码 | 描述                                        |
| ---------------------- | ------ | ------------------------------------------- |
| CONNECTNETWORK_ERROR   | 11007  | Failed to connect to the network            |
| SYSTEM_ERROR           | 20000  | System error                                |
| INVALID_HASH_ERROR     | 11055  | Invalid transaction hash                    |
| INVALID_DOMAINID_ERROR | 12007  | Domainid must be equal to or greater than 0 |

> 示例

```c
	// 初始化参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
	BifTransactionGetInfoRequest req_get_cache_data;
    BifTransactionGetInfoResponse *res_get_cache_data;
    memset(&req_get_cache_data, 0, sizeof(BifTransactionGetInfoRequest));
    req_get_cache_data.domainid = 0;
    char hash_temp[] = "2f25e770b7ede0966a920cc91503d5354be0b87e2cb3d237869449cd4290101f";
    strcpy(req_get_cache_data.hash, hash_temp);
    res_get_cache_data = get_tx_cache_data(req_get_cache_data, bif_url);
    if(res_get_cache_data->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_get_cache_data->baseResponse.code,res_get_cache_data->baseResponse.msg);
    else
        printf("%s\n", res_get_cache_data->value);
    transaction_info_response_release(res_get_cache_data);

```



### 1.5.8 parse_blob

> 接口说明

   	该接口用于blob数据解析。

> 调用方法

```java
 BifTransactionGetInfoResponse *parse_blob(BifParseBlobRequest req, const char* url);
```

> 请求参数

| 参数 | 类型  | 描述       |
| ---- | ----- | ---------- |
| blob | char* | 必填，BLOB |

> 响应数据

| 参数                  | 类型     | 描述                       |
| --------------------- | -------- | -------------------------- |
| source_address        | char*    | 交易源账号，即交易的发起方 |
| nonce                 | char*    | 账户交易序列号，必须大于0  |
| fee_limit             | char*    | 交易要求的最低费用         |
| gas_price             | char*    | 交易燃料单价               |
| operations            | Object[] | 数组                       |
| operations[].type     | char*    | 类型                       |
| operations[].pay_coin |          |                            |
|                       |          |                            |

> 错误码

| 异常                        | 错误码 | 描述                             |
| --------------------------- | ------ | -------------------------------- |
| CONNECTNETWORK_ERROR        | 11007  | Failed to connect to the network |
| SYSTEM_ERROR                | 20000  | System error                     |
| INVALID_SERIALIZATION_ERROR | 11056  | Invalid serialization            |

> 示例

```c
   // 初始化参数
   char bif_url[64] = "http://172.17.6.84:30010";
   BifTransactionGetInfoResponse *res_blob;
   BifParseBlobRequest req_blob;
   memset(&req_blob, 0 ,sizeof(BifParseBlobRequest));

   char blob_data[] = "0a296469643a6269643a6566324175414a69643164423232726b334d3676423663556331454e6e7066456510022234080752300a286469643a6269643a65664e69515045476e68545071614661746f463170397767723135325036384610081a027b7d2a080123456789abcdef30c0843d3801";
   int len = strlen(blob_data) + 1;
   req_blob.blob = (char*)malloc(len);
   memset(req_blob.blob, 0, len);
   strcpy(req_blob.blob, blob_data);
   res_blob = parse_blob(req_blob, bif_url);
    if(res_blob->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_blob->baseResponse.code,res_blob->baseResponse.msg);
    else
        printf("%s\n\n", res_blob->value);
    sdk_free(req_blob.blob); // 释放请求体中使用的内存变量接口
  	transaction_info_response_release(res_blob); // 释放最后响应体的内存资源
```

> 返回示例的响应json数据

```json
{
   "actual_fee" : 0,
   "close_time" : 0,
   "error_code" : 0,
   "error_desc" : "",
   "hash" : "b7568cad37b0fd41f9b067c99319fab4459d471437d336e2b2d2c02ae908ca23",
   "ledger_seq" : 0,
   "transaction" : {
      "fee_limit" : 1000000,
      "gas_price" : 1,
      "metadata" : "0123456789abcdef",
      "nonce" : 2,
      "operations" : [
         {
            "pay_coin" : {
               "amount" : 8,
               "dest_address" : "did:bid:efNiQPEGnhTPqaFatoF1p9wgr152P68F",
               "input" : "{}"
            },
            "type" : 7
         }
      ],
      "source_address" : "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe"
   },
   "tx_size" : 117
}
```

### 1.5.9 batch_gas_send

> 接口说明

   	该接口用于批量转移星火令。

> 调用方法

```java
 BifTransactionSubmitResponse *batch_gas_send(BifBatchGasSendRequest req, const char* url);
```

> 请求参数

| 参数                                  | 类型                  | 描述                                                         |
| ------------------------------------- | --------------------- | ------------------------------------------------------------ |
| sender_address                        | char*                 | 必填，交易源账号，即交易的发起方                             |
| private_key                           | char*                 | 必填，交易源账户私钥                                         |
| ceil_ledger_seq                       | int64_t               | 选填，区块高度限制, 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效 |
| remarks                               | char*                 | 选填，用户自定义给交易的备注                                 |
| batch_gas_send_operation[]            | BatchGasSendOperation | 必填，包含目的地址等字段的批量数据结构体数组，不能超过100个  |
| batch_gas_send_operation.dest_address | char*                 | 必填，目的地址                                               |
| batch_gas_send_operation.amount       | int64_t               | 必填，转账金额                                               |
| batch_gas_send_num                    | int                   | 必填，批量转移结构体batch_gas_send_operation的实际数量（1,100],超过100会返回错误信息 |
| gas_price                             | long                  | 选填，打包费用 ，单位是星火萤(glowstone)，默认100            |
| fee_limit                             | long                  | 选填，交易花费的手续费，单位是星火萤(glowstone)，默认1000000 |
| domainId                              | int                   | 选填，指定域ID，默认主共识域id(0)                            |

> 响应数据

| 参数              | 类型                          | 描述                 |
| ----------------- | ----------------------------- | -------------------- |
| res               | BifTransactionSubmitResponse* | 响应结构体指针       |
| res->baseResponse | BifBaseResponse               | 包含错误码信息结构体 |
| res->value        | char*                         | 包含交易信息的json串 |


> 错误码

| 异常                      | 错误码 | 描述                                           |
| ------------------------- | ------ | ---------------------------------------------- |
| INVALID_ADDRESS_ERROR     | 11006  | Invalid address                                |
| REQUEST_NULL_ERROR        | 12001  | Request parameter cannot be null               |
| PRIVATEKEY_NULL_ERROR     | 11057  | PrivateKeys cannot be empty                    |
| INVALID_DESTADDRESS_ERROR | 11003  | Invalid destAddress                            |
| INVALID_GAS_AMOUNT_ERROR  | 11026  | BIFAmount must be between 0 and Long.MAX_VALUE |
| SYSTEM_ERROR              | 20000  | System error                                   |
| INVALID_DOMAINID_ERROR    | 12007  | Domainid must be equal to or greater than 0    |


> 示例

```c
	// 初始化请求参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
    BifBatchGasSendRequest req_batch_gas_send;
    BifTransactionSubmitResponse *res_gas_send;
    memset(&req_batch_gas_send, 0, sizeof(BifBatchGasSendRequest));

    req_batch_gas_send.batch_gas_send_operation[0].amount = 100;
    strcpy(req_batch_gas_send.batch_gas_send_operation[0].dest_address, "did:bid:zf32dF6p2NA1Dzw6ySQThL2v9W3Dmbjf");
    req_batch_gas_send.batch_gas_send_operation[1].amount = 10;
    strcpy(req_batch_gas_send.batch_gas_send_operation[1].dest_address, "did:bid:zf32dF6p2NA1Dzw6ySQThL2v9W3Dmbjg");
    req_batch_gas_send.batch_gas_send_num = 2;
   
    strcpy(req_batch_gas_send.sender_address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
    strcpy(req_batch_gas_send.private_key, "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");

    res_gas_send = batch_gas_send(req_batch_gas_send, bif_url);
    if(res_gas_send->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_gas_send->baseResponse.code,res_gas_send->baseResponse.msg);
    else
        printf("%s\n", res_gas_send->value);
    transaction_submit_response_release(res_gas_send);

```

> 返回示例的响应json数据

```json
{
   "results" : [
      {
         "error_code" : 0,
         "error_desc" : "",
         "hash" : "7b161bdbb5fe5ca8d8ff4d45fd19bd98843e4cd23ea9c89d4572f848efd8b615"
      }
   ],
   "success_count" : 1
}
```



## 1.6 区块服务接口列表 

​		区块服务接口主要是区块相关的接口，目前有6个接口：

| 序号 | 接口                  | 说明                                     |
| ---- | --------------------- | ---------------------------------------- |
| 1    | get_block_number      | 该接口用于查询最新的区块高度             |
| 2    | get_transactions      | 该接口用于查询指定区块高度下的所有交易3  |
| 3    | get_block_info        | 该接口用于获取区块信息                   |
| 4    | get_block_latest_info | 该接口用于获取最新区块信息               |
| 5    | get_validators        | 该接口用于获取指定区块中所有验证节点信息 |
| 6    | get_latest_validators | 该接口用于获取最新区块中所有验证节点信息 |

### 1.6.1 get_block_number

> 接口说明

   	该接口用于查询最新的区块高度。

> 调用方法

```c
BifBlockGetNumberResponse *get_block_number(BifBlockGetTransactionsRequest req, const char* url);
```

> 请求参数

| 参数          | 类型   | 描述               |
| ------------- | ------ | ------------------ |
| domainId | int | 选填，指定域ID，默认主共识域id(0)       |
|  |  |  |

> 响应数据

| 参数                                    | 类型                       | 描述                                  |
| --------------------------------------- | -------------------------- | ------------------------------------- |
| BifBlockGetNumberResponse               | BifBlockGetNumberResponse* | 响应结构体指针                        |
| BifBlockGetNumberResponse->baseResponse | BifBaseResponse            | 包含错误码信息结构体                  |
| BifBlockGetNumberResponse->value        | char*                      | 链的响应json串数据                    |
| BifBlockGetNumberResponse->block_number | int64_t                    | 解析的最新的区块高度，对应底层字段seq |
| ...                                     |                            | 其他相关信息                          |

> 错误码

| 异常                 | 错误码 | 描述                             |
| -------------------- | ------ | -------------------------------- |
| CONNECTNETWORK_ERROR | 11007  | Failed to connect to the network |
| REQUEST_NULL_ERROR | 12001 | Request parameter cannot be null |
| INVALID_DOMAINID_ERROR | 12007  | Domainid must be equal to or greater than 0             |

> 示例

```c
	// 调用getBlockNumber接口
	char bif_url[64] = "http://test.bifcore.bitfactory.cn"; 
    BifBlockGetTransactionsRequest req;
    BifBlockGetNumberResponse *res;
    memset(&req, 0 ,sizeof(req));    
    req.domainid = 0;
    //查询区块高度
    res = get_block_number(req, bif_url);
    if(res->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res->baseResponse.code,res->baseResponse.msg);
    else
        printf("get_block_number res:%s,seq:%d\n", res->value,res->block_number);
    block_get_num_response_release(res);

```

> 返回示例的响应json数据

```json
{
   "error_code" : 0,
   "result" : {
      "header" : {
         "close_time" : 1676082051203314,
         "consensus_value_hash" : "e873d30b1864bd8d20d6591b1f98e4f72f88c1f84adc8f61a41ce0e10327e22c",
         "domain_account_hashs" : [
            {
               "account_tree_hash" : "172dd0b8f9576918186343a3fd1fa817c91d0366558a7e1c65ec82b633e9defc"
            }
         ],
         "fees_hash" : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "hash" : "34142e83e02e9dff765dac52b6762b98dd4bd454205ea9f7de3856327312d38a",
         "previous_hash" : "bbf2b83f066bf79690ce3874f954e096fb86acea6068065456ea866dfcc6e4ae",
         "seq" : 104914,
         "tx_count" : 40,
         "validators_hash" : "74353d187e62a42f628815d95d19a0c0fad8bfe0be5988ac5e66be06bf31e3bb",
         "version" : 1004
      },
      "ledger_length" : 227
   }
},seq:104914
```

### 1.6.2 get_transactions

> 接口说明

   	该接口用于查询指定区块高度下的所有交易。

> 调用方法

```java
BifBlockGetTransactionsResponse *get_transactions(BifBlockGetTransactionsRequest req, const char* url);
```

> 请求参数

| 参数        | 类型 | 描述                                  |
| ----------- | ---- | ------------------------------------- |
| block_number | long | 必填，最新的区块高度，对应底层字段seq |
| domainId    | int | 选填，指定域ID，默认主共识域id(0)       |

> 响应数据

| 参数              | 类型                             | 描述                   |
| ----------------- | -------------------------------- | ---------------------- |
| res               | BifBlockGetTransactionsResponse* | 响应结构体指针         |
| res->baseResponse | BifBaseResponse                  | 包含错误码信息的结构体 |
| res->value        | char*                            | 包含所有交易信息json串 |

> 错误码

| 异常                      | 错误码 | 描述                                        |
| ------------------------- | ------ | ------------------------------------------- |
| INVALID_BLOCKNUMBER_ERROR | 11060  | BlockNumber must bigger than 0              |
| REQUEST_NULL_ERROR        | 12001  | Request parameter cannot be null            |
| CONNECTNETWORK_ERROR      | 11007  | Failed to connect to the network            |
| INVALID_DOMAINID_ERROR    | 12007  | Domainid must be equal to or greater than 0 |

> 示例

```c
	// 初始化请求参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn"; 
	BifBlockGetTransactionsRequest req_tranction;
    BifBlockGetTransactionsResponse *res_tranction;
    memset(&req_tranction, 0, sizeof(BifBlockGetTransactionsRequest));

    req_tranction.block_number = 104928;
    res_tranction = get_transactions( req_tranction, bif_url);
    if(res_tranction->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_tranction->baseResponse.code,res_tranction->baseResponse.msg);
    else
        printf("res_tranction res:%s\n", res_tranction->value);
    block_info_response_release(res_tranction);

```

> 返回示例的响应json数据

```json
{"error_code":0,"result":{"total_count":1,"transactions":[{"actual_fee":257000,"close_time":1676082889359020,"error_code":0,"error_desc":"","hash":"3d70c0b2676f59ecd671f5d05fe53e1177fab010367048238ca18c76bb79011d","ledger_seq":104928,"signatures":[{"public_key":"b0656681fe6bbb5ef40fa464b6fb8335da40c6814be2a1fed750228deda2ac2d496e6e","sign_data":"04d5d98221e72384ab56305fd9c2d7a6a874dad102ded5b60975bc4fc0122a9c1739c437d3d7c0dab34a91b78ff0a6cb85cee7da1282183bddb42d166ae81b03"}],"transaction":{"fee_limit":1000000,"gas_price":1000,"nonce":38,"operations":[{"create_account":{"dest_address":"did:bid:zfVjEZWe3u2NPpqn7J5Cww1jK3VnW622","init_balance":10000000000,"priv":{"master_weight":1,"thresholds":{"tx_threshold":1}}},"type":1}],"source_address":"did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe"},"tx_size":257}]}}
```

### 1.6.3 get_block_info

> 接口说明

   	该接口用于获取指定区块信息。

> 调用方法

```java
BifBlockGetInfoResponse *get_block_info(BifBlockGetInfoRequest req, const char* url);
```

> 请求参数

| 参数        | 类型 | 描述                   |
| ----------- | ---- | ---------------------- |
| block_number | long | 必填，待查询的区块高度 |
| domainId    | int | 选填，指定域ID，默认主共识域id(0)       |

> 响应数据

| 参数              | 类型                     | 描述                   |
| ----------------- | ------------------------ | ---------------------- |
| res               | BifBlockGetInfoResponse* | 响应结构体指针         |
| res->baseResponse | BifBaseResponse          | 包含错误码信息的结构体 |
| res->value        | char*                    | 包含交易信息的json串   |
| ...               |                          | 其他相关信息           |

> 错误码

| 异常                      | 错误码 | 描述                                        |
| ------------------------- | ------ | ------------------------------------------- |
| INVALID_BLOCKNUMBER_ERROR | 11060  | BlockNumber must bigger than 0              |
| REQUEST_NULL_ERROR        | 12001  | Request parameter cannot be null            |
| CONNECTNETWORK_ERROR      | 11007  | Failed to connect to the network            |
| INVALID_DOMAINID_ERROR    | 12007  | Domainid must be equal to or greater than 0 |

> 示例

```c
	// 初始化请求参数
	char bif_url[64] = "http://test.bifcore.bitfactory.cn"; 
	BifBlockGetInfoRequest req_block_get_info;
    BifBlockGetInfoResponse *res_block_get_info;
    memset(&req_block_get_info, 0, sizeof(BifBlockGetInfoRequest));

    req_block_get_info.block_number = 11500;
    req_block_get_info.domainid = 0;
    res_block_get_info = get_block_info(req_block_get_info, bif_url);
    if(res_block_get_info->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_block_get_info->baseResponse.code,res_block_get_info->baseResponse.msg);
    else
        printf("res_block_get_info res:%s\n", res_block_get_info->value);
    block_info_response_release(res_block_get_info);

```

> 返回示例的响应json数据

```json
{
   "error_code" : 0,
   "result" : {
      "header" : {
         "close_time" : 1670478587429115,
         "consensus_value_hash" : "5f0ee7d09ad037d3422d75db330d147f293973a1f8bd34fdff14d5a0a42625e6",
         "domain_account_hashs" : [
            {
               "account_tree_hash" : "c1a28bf3a828d512fec523daa690ed0d14d375e64f1a4cf48ef6e95e7191acdc"
            }
         ],
         "fees_hash" : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "hash" : "b972c5f5523a99ef563794fe78190d0fc56ccda7a61b5c8a097bd9c6719ca969",
         "previous_hash" : "204f43427a44d35bb60abaae18de2c7755dc31aadb9e28a3218f3d869421812c",
         "seq" : 11500,
         "tx_count" : 10,
         "validators_hash" : "74353d187e62a42f628815d95d19a0c0fad8bfe0be5988ac5e66be06bf31e3bb",
         "version" : 1004
      },
      "leader" : "did:bid:ef2VHyvxZNZGrsrVCPZUMwmpKVMPrUKD",
      "ledger_length" : 226
   }
}
```

### 1.6.4 get_block_latest_info

> 接口说明

```
该接口用于获取最新区块信息。
```

> 调用方法

```java
BifBlockGetLatestInfoResponse *get_block_latest_info(BifBlockGetLatestInfoRequest req, const char* url);
```

> 请求参数

| 参数          | 类型   | 描述               |
| ------------- | ------ | ------------------ |
| domainId | int | 选填，指定域ID，默认主共识域id(0)       |

> 响应数据

| 参数              | 类型                           | 描述                   |
| ----------------- | ------------------------------ | ---------------------- |
| res               | BifBlockGetLatestInfoResponse* | 响应结构体指针         |
| res->baseResponse | BifBaseResponse                | 包含错误码信息的结构体 |
| res->value        | char*                          | 包含交易信息的json串   |
| ...               |                                | 其他相关信息           |


> 错误码

| 异常                 | 错误码 | 描述                             |
| -------------------- | ------ | -------------------------------- |
| CONNECTNETWORK_ERROR | 11007  | Failed to connect to the network |
| REQUEST_NULL_ERROR     | 12001  | Request parameter cannot be null            |
| INVALID_DOMAINID_ERROR | 12007  | Domainid must be equal to or greater than 0  |

> 示例

```c
	//调用get_block_latest_info 接口
	char bif_url[64] = "http://test.bifcore.bitfactory.cn"; 
	BifBlockGetLatestInfoRequest req_block_get_latest_info;
    BifBlockGetLatestInfoResponse *res_block_get_latest_info;
    memset(&req_block_get_latest_info, 0, sizeof(BifBlockGetLatestInfoRequest));
    req_block_get_latest_info.domainid = 0;
    res_block_get_latest_info = get_block_latest_info(req_block_get_latest_info, bif_url);
    if(res_block_get_latest_info->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_block_get_latest_info->baseResponse.code,res_block_get_latest_info->baseResponse.msg);
    else
        printf("res_block_get_latest_info:%s\n", res_block_get_latest_info->value);
    block_info_response_release(res_block_get_latest_info);

```

> 返回示例的响应json数据

```json
{
   "error_code" : 0,
   "result" : {
      "header" : {
         "close_time" : 1676082949358238,
         "consensus_value_hash" : "45640c6fc1e75e3232be206603a4b9d30265e21217dd6c91aa21577929ec85dc",
         "domain_account_hashs" : [
            {
               "account_tree_hash" : "eb3db110dcfdf7409af56ef6cced70c33a2f80aeadeae03867a6c0dc0113c99d"
            }
         ],
         "fees_hash" : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "hash" : "ad9d52b35f3c3bffe42baf5d83c88cb64a7f37f261092bcc1e3371d2ee1cbfdd",
         "previous_hash" : "dace74ed9a144756e36bd29f8a4cfc68890d41cb5b77ddaaa0494e77d41fb856",
         "seq" : 104929,
         "tx_count" : 41,
         "validators_hash" : "74353d187e62a42f628815d95d19a0c0fad8bfe0be5988ac5e66be06bf31e3bb",
         "version" : 1004
      },
      "ledger_length" : 227
   }
}
```

### 1.6.5 get_validators

> 接口说明

   	该接口用于获取指定区块中所有验证节点信息。

> 调用方法

```java
BifBlockGetValidatorsResponse *get_validators(BifBlockGetValidatorsRequest req, const char* url);
```

> 请求参数

| 参数        | 类型 | 描述                              |
| ----------- | ---- | --------------------------------- |
| block_number | int64_t | 必填，待查询的区块高度，必须大于0 |
| domainId    | int | 选填，指定域ID，默认主共识域id(0)   |

> 响应数据

| 参数              | 类型                           | 描述                      |
| ----------------- | ------------------------------ | ------------------------- |
| res               | BifBlockGetValidatorsResponse* | 响应结构体指针            |
| res->baseResponse | BifBaseResponse                | 包含错误码信息的结构体    |
| res->value        | char*                          | 包含validator信息的json串 |

> 错误码

| 异常                      | 错误码 | 描述                                        |
| ------------------------- | ------ | ------------------------------------------- |
| INVALID_BLOCKNUMBER_ERROR | 11060  | BlockNumber must bigger than 0              |
| REQUEST_NULL_ERROR        | 12001  | Request parameter cannot be null            |
| CONNECTNETWORK_ERROR      | 11007  | Failed to connect to the network            |
| INVALID_DOMAINID_ERROR    | 12007  | Domainid must be equal to or greater than 0 |

> 示例

```c
	// 初始化请求参数
	//查询指定区块高度的validator信息
	char bif_url[64] = "http://test.bifcore.bitfactory.cn"; 
    BifBlockGetValidatorsRequest req_get_validators;
    BifBlockGetValidatorsResponse *res_get_validators;
    memset(&req_get_validators, 0, sizeof(BifBlockGetValidatorsRequest));

    req_get_validators.block_number = 1150;
    req_get_validators.domainid = 0;
    res_get_validators = get_validators(req_get_validators, bif_url);
    if(res_get_validators->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_get_validators->baseResponse.code,res_get_validators->baseResponse.msg);
    else
        printf("res_get_validators:%s\n", res_get_validators->value);
    block_info_response_release(res_get_validators);

```

> 返回示例的响应json数据

```json
{
   "error_code" : 0,
   "result" : {
      "header" : {
         "account_tree_hash" : "0418c603930b6a0e0bb920419ea338f9ea7f747172415cec177a26487ec3334e",
         "close_time" : 1678173805694770,
         "consensus_value_hash" : "64844754ed3f33bb1c27b5a183dd13533ff38a20453251df4e637d89f808e180",
         "domain_account_hashs" : [
            {
               "account_tree_hash" : "0418c603930b6a0e0bb920419ea338f9ea7f747172415cec177a26487ec3334e"
            },
            {
               "account_tree_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
               "domain_id" : 24
            },
            {
               "account_tree_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
               "domain_id" : 20
            },
            {
               "account_tree_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
               "domain_id" : 22
            },
            {
               "account_tree_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
               "domain_id" : 21
            },
            {
               "account_tree_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
               "domain_id" : 23
            }
         ],
         "fees_hash" : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "hash" : "19f7da42d022480e581bda0b2164ceba0852c9100b9ecf7cab12aba4ee7630d1",
         "previous_hash" : "92f0c968d35aa835548b120e20d8965c294d964219764851227b1e1412287e5f",
         "seq" : 727970,
         "tx_count" : 2,
         "validators_hash" : "3e798cbadf0ed8cfe3795584bb710c311a107f5fae5087bbafd8237135fa67c8",
         "version" : 1006
      },
      "leader" : "did:bid:efve9mJuyQTpDpNaCNnKNaPZQaw3v1Rm",
      "ledger_length" : 417,
      "validators" : [
         "did:bid:zfMRFMtT19zDTqPTjJbM863m91V931JV",
         "did:bid:zfu4giCMQYLgBmF8kXJD9yFbqxJeMR6t",
         "did:bid:zfFe8hHtRjpTGirtN2ivzNWqkCChPg5W",
         "did:bid:zf2bbxDwdzm4g4fJNTH2ah6gbHu6PdAX2",
         "did:bid:ef22cLJeoxaFfjjN8y9x4YzDZ61H1zzBi",
         "did:bid:ef25p7T2L5Rrf2JTVhmdEY4PFMZR7NiVS",
         "did:bid:efve9mJuyQTpDpNaCNnKNaPZQaw3v1Rm",
         "did:bid:efDu7qbPfT2oDTCg8nwuAgnPDZBpdWkC"
      ]
   }
}
```



### 1.6.6 get_latest_validators

> 接口说明

   	该接口用于获取最新区块中所有验证节点信息。

> 调用方法

```java
BifBlockGetLatestValidatorsResponse * get_latest_validators(BifBlockGetValidatorsRequest req, const char* url);
```

> 请求参数

| 参数        | 类型 | 描述                              |
| ----------- | ---- | --------------------------------- |
| domainId    | int | 选填，指定域ID，默认主共识域id(0)   |
|  |  |  |

> 响应数据

| 参数              | 类型                           | 描述                          |
| ----------------- | ------------------------------ | ----------------------------- |
| res               | BifBlockGetValidatorsResponse* | 响应结构体指针                |
| res->baseResponse | BifBaseResponse                | 包含错误码信息的结构体        |
| res->value        | char*                          | 包含所有validator信息的json串 |

> 错误码

| 异常                 | 错误码 | 描述                             |
| -------------------- | ------ | -------------------------------- |
| CONNECTNETWORK_ERROR | 11007  | Failed to connect to the network |
| REQUEST_NULL_ERROR     | 12001  | Request parameter cannot be null            |
| INVALID_DOMAINID_ERROR  | 12007  | Domainid must be equal to or greater than 0  |

> 示例

```c
	//调用 get_latest_validators 接口
	char bif_url[64] = "http://test.bifcore.bitfactory.cn";
	BifBlockGetValidatorsRequest req_latest_validators;
    BifBlockGetLatestValidatorsResponse *res_latest_validators;
    memset(&req_latest_validators, 0, sizeof(BifBlockGetValidatorsRequest));
    req_latest_validators.domainid = 0;
    res_latest_validators = get_latest_validators(req_latest_validators, bif_url);
    if(res_latest_validators->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_latest_validators->baseResponse.code,res_latest_validators->baseResponse.msg);
    else
        printf("res_latest_validators:%s\n", res_latest_validators->value);
    block_info_response_release(res_latest_validators);

```

> 返回示例的响应json数据

```json
{
   "error_code" : 0,
   "result" : {
      "header" : {
         "account_tree_hash" : "fc9928d2db4162763373154c877eaf9b61dafe5fe7e720a126a3dbb46fbe42ab",
         "close_time" : 1678176849926891,
         "consensus_value_hash" : "73d5e0880b8387b414e3bf80d5703f54e993e0a322b4ec58473a6f4c0941eaab",
         "domain_account_hashs" : [
            {
               "account_tree_hash" : "fc9928d2db4162763373154c877eaf9b61dafe5fe7e720a126a3dbb46fbe42ab"
            },
            {
               "account_tree_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
               "domain_id" : 24
            },
            {
               "account_tree_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
               "domain_id" : 20
            },
            {
               "account_tree_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
               "domain_id" : 22
            },
            {
               "account_tree_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
               "domain_id" : 21
            },
            {
               "account_tree_hash" : "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
               "domain_id" : 23
            }
         ],
         "fees_hash" : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "hash" : "76d7dc7788434aef8bc00b038ef6878cfb37afc9e5d6aa6acdd378e33334d56b",
         "previous_hash" : "516732812931c07efb312869a2a256e1d160a425520e29c862f35363b1f6cea0",
         "seq" : 728019,
         "tx_count" : 3482513,
         "validators_hash" : "3e798cbadf0ed8cfe3795584bb710c311a107f5fae5087bbafd8237135fa67c8",
         "version" : 1006
      },
      "leader" : "did:bid:efve9mJuyQTpDpNaCNnKNaPZQaw3v1Rm",
      "ledger_length" : 420
   }
}
```



## 1.7 SDK智能合约开发流程

本节给出一个基于SDK的完整智能合约开发流程。

**一定要灵活使用星火区块链浏览器 http://test-explorer.bitfactory.cn/, 账户，交易，合约hash都可以在上面搜索查询。**

### 4.7.1 概述

做合约开发，一般需要以下几个步骤：

1. 创建一个账号，并且获得XHT，才能发起后续交易
2. 编写合约，建议基于javascript编写
3. 编译和部署合约
4. 调用和读取合约

### 1.7.2 账号创建

通过调用getBidAndKeyPair()就可以离线创建一个随机地址。

```java
KeyPairEntity key_pair_entity;
memset(&key_pair_entity, 0,sizeof(KeyPairEntity));
int ret = get_bid_and_key_pair(&key_pair_entity);
	
printf("public BID address %s\n", key_pair_entity.enc_address);
printf("private key %s\n", key_pair_entity.enc_private_key);
```
建议将得到的地址和对应私钥都稳妥保存，之后就用这个地址开始后续的开发，私钥一定不能泄露。

### 1.7.3 初始化星火链URL

**之后的操作都需要链网进行，需要初始化星火链URL链接到星火链。**

```java
每个接口调用前都需要对应星火链的地址
char bif_url[64] = "http://172.17.6.84:30010"; 
```

url地址初始化之后，我们可以通过调用链上方法进行开发。

### 1.7.4 查看账户状态

1. 首先我们记录了最开始生成的账户地址和私钥 

```c
char* address = "did:bid:efKkF5uKsopAishxkYja4ULRJhrhrJQU";
char* privateKey = "priSPKqB8wCf8GtiKCG1yN3RHPVLbfcXLmkFfHLGjSgrMRD7AJ";
```

2. 通过星火SDK查看账户状态

```java
	BifAccountGetInfoRequest req_account_base;
    BifAccountResponse *res_account_base;
    memset(&req_account_base, 0, sizeof(BifAccountGetInfoRequest));
    strcpy(req_account_base.address, address);
    //req_account_base.domainid = 0;
    //获取账户信息接口的函数
    res_account_base = get_account(req_account_base, bif_url);
	if(res_account_base->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_account_base->baseResponse.code,res_account_base->baseResponse.msg);
    else
        printf("%s\n", res_account_base->value);

    sdk_free(res_account_base->value);
    sdk_free(res_account_base);
```
这里会报错，因为该账户还没有过任何操作，所以星火链上没有记录。

所有链上操作都需要耗费星火令(XHT)，因此您需要从其他地方获取XHT到这个账户供操作。

获取星火令之后再查看账户状态，得到正确返回如下：

```json
{"address":"did:bid:efKkF5uKsopAishxkYja4ULRJhrhrJQU","balance":10000000000,"nonce":0}
```

### 1.7.5 合约开发

做一个完整的链上合约开发主要包括以下几个部分：

1. 合约编写

合约具体编写可以参考[开发手册](https://bif-core-dev-doc.readthedocs.io/zh_CN/latest/)。这里直接列出写好的javascript智能合约。

```javascript
"use strict";

function queryById(id) {
    let data = Chain.load(id);
    return data;
}

function query(input) {
    input = JSON.parse(input);
    let id = input.id;
    let object = queryById(id);
    return object;
}

function main(input) {
    input = JSON.parse(input);
    Chain.store(input.id, input.data);
}

function init(input) {
    return;
}
```

该合约做的事情比较简单，就是实现了基于key的存储和读取。

2. 合约部署

写完合约后，需要将合约部署到链上(注意需要消耗XHT，确保账号有足够XHT)。示例代码如下：

```java
//部署合约
//合约代码，注意转义
	String contractCode = "\"use strict\";function queryById(id) {    let data = Chain.load(id);    return data;}function query(input) {    input = JSON.parse(input);    let id = input.id;    let object = queryById(id);    return object;}function main(input) {    input = JSON.parse(input);    Chain.store(input.id, input.data);}function init(input) {    return;}";

 	BifContractGetInfoResponse *res_create_contract;
    BifContractCreateRequest req_create_contract;
    memset(&req_create_contract, 0, sizeof(BifContractCreateRequest));
   
    req_create_contract.payload = sdsempty(); //初始化sds变量
    req_create_contract.payload = sdscpy(req_create_contract.payload, contractCode);//类似库函数memcpy的封装
    //req_create_contract.ceil_ledger_seq = 0;
    //req_create_contract.domainid = 0;
    req_create_contract.gas_price = 10;
    req_create_contract.fee_limit = 100000000;

    strcpy(req_create_contract.private_key, "priSPKqB8wCf8GtiKCG1yN3RHPVLbfcXLmkFfHLGjSgrMRD7AJ");
    strcpy(req_create_contract.sender_address, "did:bid:efKkF5uKsopAishxkYja4ULRJhrhrJQU");
    req_create_contract.contract_type = TYPE_V8;
    req_create_contract.init_balance = 100000000;
   
    res_create_contract = contract_create(req_create_contract, bif_url);
    if(res_create_contract->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_create_contract->baseResponse.code,res_create_contract->baseResponse.msg);
    else
        printf("%s\n", res_create_contract->value);
    sdk_free(res_create_contract->value);
    sdk_free(res_create_contract);
    sdsfree(req_create_contract.payload);
```

如果部署成功，返回里会拿到这个交易的HASH。

```json
{"hash":"b25567a482e674d79ac5f9b5f6601f27b676dde90a6a56539053ec882a99854f"}
```

这里我们记录下这个交易HASH，然后查询生成的合约地址。

3. 合约地址查询

基于刚刚得到的交易HASH查询生成的合约地址:

```java
	BifContractGetAddressRequest req_contract_addr;
    BifContractGetInfoResponse *res_contract_addr;
    memset(&req_contract_addr, 0 ,sizeof(BifContractGetAddressRequest));
    //req_contract_addr.domainid = 21;
    //hash根据实际节点交易生成的值即可
    char hash_test[] = "b25567a482e674d79ac5f9b5f6601f27b676dde90a6a56539053ec882a99854f";
    strcpy(req_contract_addr.hash, hash_test);
    res_contract_addr = get_contract_address(req_contract_addr, bif_url);

    if(res_contract_addr->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_contract_addr->baseResponse.code,res_contract_addr->baseResponse.msg);
    else
        printf("get_contract_address:%s\n", res_contract_addr->value);
    sdk_free(res_contract_addr->value);
    sdk_free(res_contract_addr);
```

收到返回如下: 

```json
{"contract_address_infos":[{"contract_address":"did:bid:efSvDJivc2A4iqurRkUPzmpT5kB3nkNg","operation_index":0}]}
```

生成的合约地址即为: did:bid:efSvDJivc2A4iqurRkUPzmpT5kB3nkNg.

3. 合约调用

有了合约地址，我们就可以开始调用合约，这里我们set一个key value对到刚刚合约里，对照我们刚刚javascript合约的main函数，调用的input为:

```json
{"id":"test", "data": "test"}
```

也就是在key "test"下写入 "test"值。

合约调用的java代码如下:
```java

//转义后input
	char* input = "{\"id\":\"test\", \"data\": \"test\"}";

	BifContractGetInfoResponse *res_contract_invoke;
    BifContractInvokeRequest req_contract_invoke;
    memset(&req_contract_invoke,0, sizeof(BifContractInvokeRequest));
    req_contract_invoke.input = sdsempty();
    req_contract_invoke.input = sdscpy(req_contract_invoke.input,input);
    //根据实际部署节点的合约地址等测试信息
    strcpy(req_contract_invoke.contract_address, "did:bid:efSvDJivc2A4iqurRkUPzmpT5kB3nkNg");
    strcpy(req_contract_invoke.sender_address, "did:bid:efKkF5uKsopAishxkYja4ULRJhrhrJQU");
    strcpy(req_contract_invoke.private_key, "priSPKqB8wCf8GtiKCG1yN3RHPVLbfcXLmkFfHLGjSgrMRD7AJ");
    req_contract_invoke.amount = 0;

    res_contract_invoke = contract_invoke(req_contract_invoke, bif_url);
    if(res_contract_invoke->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_contract_invoke->baseResponse.code,res_contract_invoke->baseResponse.msg);
    else
        printf("%s\n", res_contract_invoke->value);
    sdk_free(res_contract_invoke->value);
    sdk_free(res_contract_invoke);
    sdsfree(req_contract_invoke.input);
```

调用成功后，我们又会得到调用交易的HASH：

```json
{"hash":"c79835265e908f7f06d4fc2c61ef3fd046ae5252675e4671271bd921ad8fde89"}
```

4. 合约读取

调用成功后，我们还需要读取链上数据，根据我们的javascript合约，读取的input为
```json
{"id":"test"}
```
表示我们需要读取id "test"下的内容，使用SDK的读取代码如下:

```java

	char* callInput = "{\"id\":\"test\"}";
	BifContractGetInfoResponse *res_contract_query;
    BifContractCallRequest req_contract_query;
    memset(&req_contract_query,0, sizeof(BifContractCallRequest));

    req_contract_query.input = sdsempty();
    req_contract_query.input = sdscpy(req_contract_query.input, callInput);
    strcpy(req_contract_query.contract_address, "did:bid:efSvDJivc2A4iqurRkUPzmpT5kB3nkNg");
    strcpy(req_contract_query.source_address, "did:bid:efKkF5uKsopAishxkYja4ULRJhrhrJQU");

    res_contract_query = contract_query(req_contract_query, bif_url);
    if(res_contract_query->baseResponse.code != 0)
        printf("code:%d,msg:%s\n",res_contract_query->baseResponse.code,res_contract_query->baseResponse.msg);
    else
        printf("%s\n", res_contract_query->value);
    sdk_free(res_contract_query->value);
    sdk_free(res_contract_query);
```

读取成功的结果如下:

```json
{"query_rets":[{"result":{"type":"string","value":"test"}}]}
```

至此，我们就完成了一个完整的合约编写，部署，调用和读取的过程。


## 1.8 错误码

| 异常                                      | 错误码 | 描述                                                         |
| ----------------------------------------- | ------ | ------------------------------------------------------------ |
| ACCOUNT_CREATE_ERROR                      | 11001  | Failed to create the account                                 |
| INVALID_SOURCEADDRESS_ERROR               | 11002  | Invalid sourceAddress                                        |
| INVALID_DESTADDRESS_ERROR                 | 11003  | Invalid destAddress                                          |
| INVALID_INITBALANCE_ERROR                 | 11004  | InitBalance must be between 1 and Long.MAX_VALUE             |
| SOURCEADDRESS_EQUAL_DESTADDRESS_ERROR     | 11005  | SourceAddress cannot be equal to destAddress                 |
| INVALID_ADDRESS_ERROR                     | 11006  | Invalid address                                              |
| CONNECTNETWORK_ERROR                      | 11007  | Failed to connect to the network                             |
| INVALID_ISSUE_AMOUNT_ERROR                | 11008  | Amount of the token to be issued must be between 1 and Long.MAX_VALUE |
| NO_METADATAS_ERROR                        | 11010  | The account does not have the metadatas                      |
| INVALID_DATAKEY_ERROR                     | 11011  | The length of key must be between 1 and 1024                 |
| INVALID_DATAVALUE_ERROR                   | 11012  | The length of value must be between 0 and 256000             |
| INVALID_DATAVERSION_ERROR                 | 11013  | The version must be equal to or greater than 0               |
| INVALID_MASTERWEIGHT_ERROR                | 11015  | MasterWeight must be between 0 and (Integer.MAX_VALUE * 2L + 1) |
| INVALID_SIGNER_ADDRESS_ERROR              | 11016  | Invalid signer address                                       |
| INVALID_SIGNER_WEIGHT_ERROR               | 11017  | Signer weight must be between 0 and (Integer.MAX_VALUE * 2L + 1) |
| INVALID_TX_THRESHOLD_ERROR                | 11018  | TxThreshold must be between 0 and Long.MAX_VALUE             |
| INVALID_TYPETHRESHOLD_TYPE_ERROR          | 11019  | Type of TypeThreshold is invalid                             |
| INVALID_TYPE_THRESHOLD_ERROR              | 11020  | TypeThreshold must be between 0 and Long.MAX_VALUE           |
| INVALID_AMOUNT_ERROR                      | 11024  | Amount must be between 0 and Long.MAX_VALUE                  |
| INVALID_CONTRACT_HASH_ERROR               | 11025  | Invalid transaction hash to create contract                  |
| INVALID_GAS_AMOUNT_ERROR                  | 11026  | bifAmount must be between 0 and Long.MAX_VALUE               |
| INVALID_ISSUER_ADDRESS_ERROR              | 11027  | Invalid issuer address                                       |
| INVALID_CONTRACTADDRESS_ERROR             | 11037  | Invalid contract address                                     |
| CONTRACTADDRESS_NOT_CONTRACTACCOUNT_ERROR | 11038  | contractAddress is not a contract account                    |
| SOURCEADDRESS_EQUAL_CONTRACTADDRESS_ERROR | 11040  | SourceAddress cannot be equal to contractAddress             |
| INVALID_FROMADDRESS_ERROR                 | 11041  | Invalid fromAddress                                          |
| FROMADDRESS_EQUAL_DESTADDRESS_ERROR       | 11042  | FromAddress cannot be equal to destAddress                   |
| INVALID_SPENDER_ERROR                     | 11043  | Invalid spender                                              |
| PAYLOAD_EMPTY_ERROR                       | 11044  | Payload cannot be empty                                      |
| INVALID_CONTRACT_TYPE_ERROR               | 11047  | Invalid contract type                                        |
| INVALID_NONCE_ERROR                       | 11048  | Nonce must be between 1 and Long.MAX_VALUE                   |
| INVALID_GASPRICE_ERROR                    | 11049  | GasPrice must be between 0 and Long.MAX_VALUE                |
| INVALID_FEELIMIT_ERROR                    | 11050  | FeeLimit must be between 0 and Long.MAX_VALUE                |
| OPERATIONS_EMPTY_ERROR                    | 11051  | Operations cannot be empty                                   |
| INVALID_CEILLEDGERSEQ_ERROR               | 11052  | CeilLedgerSeq must be equal to or greater than 0             |
| OPERATIONS_ONE_ERROR                      | 11053  | One of the operations cannot be resolved                     |
| INVALID_SIGNATURENUMBER_ERROR             | 11054  | SignagureNumber must be between 1 and Integer.MAX_VALUE      |
| INVALID_HASH_ERROR                        | 11055  | Invalid transaction hash                                     |
| INVALID_SERIALIZATION_ERROR               | 11056  | Invalid serialization                                        |
| PRIVATEKEY_NULL_ERROR                     | 11057  | PrivateKeys cannot be empty                                  |
| PRIVATEKEY_ONE_ERROR                      | 11058  | One of privateKeys is invalid                                |
| SIGNDATA_NULL_ERROR                       | 11059  | SignData cannot be empty                                     |
| INVALID_BLOCKNUMBER_ERROR                 | 11060  | BlockNumber must be bigger than 0                            |
| PUBLICKEY_NULL_ERROR                      | 11061  | PublicKey cannot be empty                                    |
| URL_EMPTY_ERROR                           | 11062  | Url cannot be empty                                          |
| INVALID_OPTTYPE_ERROR                     | 11064  | OptType must be between 0 and 2                              |
| GET_ALLOWANCE_ERROR                       | 11065  | Failed to get allowance                                      |
| SIGNATURE_EMPTY_ERROR                     | 11067  | The signatures cannot be empty                               |
| REQUEST_NULL_ERROR                        | 12001  | Request parameter cannot be null                             |
| CONNECTN_BLOCKCHAIN_ERROR                 | 19999  | Failed to connect to the blockchain                          |
| SYSTEM_ERROR                              | 20000  | System error                                                 |
| INVALID_CONTRACTBALANCE_ERROR             | 12002  | ContractBalance must be between 1 and Long.MAX_VALUE         |
| INVALID_PRITX_FROM_ERROR                  | 12003  | Invalid Private Transaction Sender                           |
| INVALID_PRITX_PAYLAOD_ERROR               | 12004  | Invalid Private Transaction payload                          |
| INVALID_PRITX_TO_ERROR                    | 12005  | Invalid Private Transaction recipient list                   |
| INVALID_PRITX_HASH_ERROR                  | 12006  | Invalid Private Transaction Hash                             |
| INVALID_DOMAINID_ERROR                    | 12007  | Domainid must be equal to or greater than 0                  |

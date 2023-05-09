
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
 * @file: ecc_sm2.c
 */
#include "ecc_sm2.h"
#include "openssl/aes.h"
#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/ec.h"
#include "openssl/ecdh.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"
#include "openssl/rand.h"
#include "openssl/sha.h"
#include "openssl/x509.h"
#include "crypto.h"
#define free_bn(x)                                                             \
  do {                                                                         \
    if (x != NULL)                                                             \
      BN_free(x);                                                              \
  } while (0)

#define free_ec_point(x)                                                       \
  do {                                                                         \
    if (x != NULL)                                                             \
      EC_POINT_free(x);                                                        \
  } while (0)
#define MAX_BITS 128;

EC_GROUP *cfca_group_ = NULL;
void init(SM2_DATA *sm2_data, struct EC_GROUP *curv) {
  sm2_data->valid = false;
  sm2_data->group = curv;
  sm2_data->da = BN_new();
  sm2_data->pkey = EC_POINT_new(curv);
}
void sm2_free(SM2_DATA sm2_data) {
  free_bn(sm2_data.da);
  free_ec_point(sm2_data.pkey);
}

struct EC_GROUP *get_cfca_group() {
  if (cfca_group_ != NULL) {
    printf("cfca_group_ has exist\n");
    return cfca_group_;
  }
  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  EC_POINT *G = NULL;
  BIGNUM *p = BN_CTX_get(ctx);
  BIGNUM *a = BN_CTX_get(ctx);
  BIGNUM *b = BN_CTX_get(ctx);
  BIGNUM *xG = BN_CTX_get(ctx);
  BIGNUM *yG = BN_CTX_get(ctx);
  BIGNUM *n = BN_CTX_get(ctx);
  do {
    BN_hex2bn(
        &p, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
    BN_hex2bn(
        &a, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
    BN_hex2bn(
        &b, "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
    BN_hex2bn(
        &xG,
        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
    BN_hex2bn(
        &yG,
        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
    BN_hex2bn(
        &n, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
    cfca_group_ = EC_GROUP_new(EC_GFp_mont_method());
    if (!EC_GROUP_set_curve_GFp(cfca_group_, p, a, b, ctx)) {
      break;
    }
    G = EC_POINT_new(cfca_group_);
    EC_POINT_set_affine_coordinates_GFp(cfca_group_, G, xG, yG, ctx);
    if (!EC_GROUP_set_generator(cfca_group_, G, n, BN_value_one())) {
      break;
    }
  } while (false);
  free_ec_point(G);
  return cfca_group_;
}

char *bn2_fixed_string(struct BIGNUM *bn, int len, int *out_len) {
  char *result = (char *)malloc(256);
  memset(result, 0, 256);
  unsigned char tmp[1024] = {0};

  int l = BN_bn2bin(bn, tmp);
  if (l <= len) {
    int i = 0;
    for (i = 0; i < len - l; i++) {
      // result[i] = '0';
      result[i] = 0x00;
    }
    memcpy(result + (len - l), tmp, l);
    result[len] = '\0';
  } else {
    memcpy(result, (char *)(tmp + (l - len)), len);
    result[len] = '\0';
  }
  *out_len = len;
  return result;
}
struct EC_GROUP *new_group(GROUP_TYPE type, char *phex, char *ahex, char *bhex,
                           char *xGhex, char *yGhex, char *nhex) {
  EC_POINT *G = NULL;
  EC_POINT *R = NULL;
  EC_GROUP *group = NULL;
  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  BIGNUM *p = BN_CTX_get(ctx);
  BIGNUM *a = BN_CTX_get(ctx);
  BIGNUM *b = BN_CTX_get(ctx);
  BIGNUM *xG = BN_CTX_get(ctx);
  BIGNUM *yG = BN_CTX_get(ctx);
  BIGNUM *n = BN_CTX_get(ctx);
  BIGNUM *bn_4a3 = BN_CTX_get(ctx);
  BIGNUM *bn_27b2 = BN_CTX_get(ctx);
  BIGNUM *bn_4a3_add_27b2 = BN_CTX_get(ctx);
  BIGNUM *bn_191 = BN_CTX_get(ctx);

  BN_hex2bn(&p, phex);
  BN_hex2bn(&a, ahex);
  BN_hex2bn(&b, bhex);
  BN_hex2bn(&xG, xGhex);
  BN_hex2bn(&yG, yGhex);
  BN_hex2bn(&n, nhex);
  BN_hex2bn(&bn_191, "400000000000000000000000000000000000000000000000");
  bool ret = false;
  do {
    if (type == GFP) {
      // n>2^191
      if (BN_cmp(n, bn_191) <= 0) {
        break;
      }
      if (!BN_is_prime_ex(p, BN_prime_checks, NULL, NULL)) {
        break;
      }
      if (!BN_is_odd(p)) {
        break;
      }
      group = EC_GROUP_new(EC_GFp_mont_method());
      if (group == NULL) {
        break;
      }
      if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) {
        break;
      }
      G = EC_POINT_new(group);
      EC_POINT_set_affine_coordinates_GFp(group, G, xG, yG, ctx);

      if (!EC_GROUP_set_generator(group, G, n, BN_value_one())) {
        break;
      }
      // bn_4a3=4*a^3
      BN_sqr(bn_4a3, a, ctx);
      BN_mul(bn_4a3, bn_4a3, a, ctx);
      BN_mul_word(bn_4a3, 4);
      // bn_27b2=27*b^2
      BN_mul(bn_27b2, b, b, ctx);
      BN_mul_word(bn_27b2, 27);
      // bn_4a3_add_27b2=(4*a^3 + 27*b^)2 mod p
      BN_mod_add(bn_4a3_add_27b2, bn_4a3, bn_27b2, p, ctx);
      if (BN_is_zero(bn_4a3_add_27b2)) {
        break;
      }
      BIGNUM *y2modp = BN_CTX_get(ctx);
      BN_mod_mul(y2modp, yG, yG, p, ctx);
      BIGNUM *tmp = BN_CTX_get(ctx);
      BN_mul(tmp, xG, xG, ctx);
      BN_mul(tmp, tmp, xG, ctx);
      BIGNUM *tmp2 = BN_CTX_get(ctx);
      BN_mul(tmp2, a, xG, ctx);
      BN_add(tmp2, tmp2, b);
      BIGNUM *x3axb = BN_CTX_get(ctx);
      BN_mod_add(x3axb, tmp, tmp2, p, ctx);
      if (BN_cmp(y2modp, x3axb) != 0) {
        break;
      }
      // n is a prime number
      if (!BN_is_prime_ex(n, BN_prime_checks, NULL, NULL)) {
        break;
      }
      R = EC_POINT_new(group);
      EC_POINT_mul(group, R, n, NULL, NULL, ctx);
      if (EC_POINT_is_at_infinity(group, R) != 1) {
        break;
      }
      ret = true;
    } else {
      group = EC_GROUP_new(EC_GF2m_simple_method());
      if (group == NULL) {
        break;
      }
      if (!EC_GROUP_set_curve_GF2m(group, p, a, b, ctx)) {
        break;
      }
      G = EC_POINT_new(group);
      EC_POINT_set_affine_coordinates_GF2m(group, G, xG, yG, ctx);

      if (!EC_GROUP_set_generator(group, G, n, BN_value_one())) {
        break;
      }
    }

    if (!EC_GROUP_check(group, ctx)) {
      EC_GROUP_free(group);
      return NULL;
      break;
    }

  } while (false);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  free_ec_point(R);
  free_ec_point(G);
  return group;
}
char *get_za(struct EC_GROUP *group, char *id, const struct EC_POINT *pkey) {
  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);

  BIGNUM *xA = BN_CTX_get(ctx);
  BIGNUM *yA = BN_CTX_get(ctx);
  // unsigned char bin[MAX_BITS];
  int len = 0;
  if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
      NID_X9_62_prime_field) {
    EC_POINT_get_affine_coordinates_GFp(group, pkey, xA, yA, NULL);
  } else {
    EC_POINT_get_affine_coordinates_GF2m(group, pkey, xA, yA, NULL);
  }

  const EC_POINT *G = EC_GROUP_get0_generator(group);
  BIGNUM *xG = BN_CTX_get(ctx);
  BIGNUM *yG = BN_CTX_get(ctx);
  if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
      NID_X9_62_prime_field)
    EC_POINT_get_affine_coordinates_GFp(group, G, xG, yG, ctx);
  else
    EC_POINT_get_affine_coordinates_GF2m(group, G, xG, yG, ctx);

  BIGNUM *a = BN_CTX_get(ctx);
  BIGNUM *b = BN_CTX_get(ctx);
  EC_GROUP_get_curve_GFp(group, NULL, a, b, ctx);
  /// The national standard does not have English annotations
  //////////////////////////////////////////////////////////////////////////
  uint32_t entla = strlen(id) * 8;
  char za[1024] = {0};
  int out_len;
  // Combine ENTLA
  unsigned char c1 = entla >> 8;
  unsigned char c2 = entla & 0xFF;
  za[0] = c1;
  za[1] = c2;
  // Combine user ID
  memcpy(za + 2, id, strlen(id));
  int za_1_len = strlen(id) + 2;
  // za[strlen(id) + 2] = '\0';

  // Combine a
  char *bn_ptr = bn2_fixed_string(a, 32, &out_len);
  memcpy(za + za_1_len, bn_ptr, out_len);
  int za_2_len = za_1_len + out_len;
  out_len = 0;
  if (bn_ptr) {
    free(bn_ptr);
    bn_ptr = NULL;
  }
  // Combine b
  bn_ptr = bn2_fixed_string(b, 32, &out_len);
  memcpy(za + za_2_len, bn_ptr, out_len);
  int za_3_len = za_2_len + out_len;
  out_len = 0;
  if (bn_ptr) {
    free(bn_ptr);
    bn_ptr = NULL;
  }
  // Combine xG
  bn_ptr = bn2_fixed_string(xG, 32, &out_len);
  memcpy(za + za_3_len, bn_ptr, out_len);
  int za_4_len = za_3_len + out_len;
  out_len = 0;
  if (bn_ptr) {
    free(bn_ptr);
    bn_ptr = NULL;
  }
  // Combine yG
  bn_ptr = bn2_fixed_string(yG, 32, &out_len);
  memcpy(za + za_4_len, bn_ptr, out_len);
  int za_5_len = za_4_len + out_len;
  out_len = 0;
  if (bn_ptr) {
    free(bn_ptr);
    bn_ptr = NULL;
  }
  // Combine xA
  bn_ptr = bn2_fixed_string(xA, 32, &out_len);
  memcpy(za + za_5_len, bn_ptr, out_len);
  int za_6_len = za_5_len + out_len;
  out_len = 0;
  if (bn_ptr) {
    free(bn_ptr);
    bn_ptr = NULL;
  }
  // Combine yA
  bn_ptr = bn2_fixed_string(yA, 32, &out_len);
  memcpy(za + za_6_len, bn_ptr, out_len);
  int za_7_len = za_6_len + out_len;
  out_len = 0;
  if (bn_ptr) {
    free(bn_ptr);
    bn_ptr = NULL;
  }
  za[za_7_len] = '\0';

  char *result = (char *)malloc(128);
  memset(result, 0, 128);
  sm3_crypto(za, za_7_len, result);

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  // printf("za=%s\n", String::BinToHexString(za).c_str());
  // printf("ZA=%s\n", String::BinToHexString(ZA).c_str());
  return result;
}

bool from_skey_bin(char *skey_bin, int skey_len, SM2_DATA *sm2_data) {
  sm2_data->valid = false;
  memcpy(sm2_data->skey_bin, skey_bin, skey_len);
  sm2_data->skey_bin[skey_len] = '\0';
  sm2_data->skey_len = skey_len;
  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  BIGNUM *x = BN_CTX_get(ctx);
  BIGNUM *y = BN_CTX_get(ctx);
  BIGNUM *order = BN_CTX_get(ctx);
  EC_GROUP_get_order(sm2_data->group, order, ctx);
  do {
    BN_bin2bn((const unsigned char *)sm2_data->skey_bin, sm2_data->skey_len,
              sm2_data->da);
    if (BN_cmp(sm2_data->da, order) == 0) {
      strcpy(sm2_data->error, "dA must be less than order i.e. n ");
      break;
    }
    if (!EC_POINT_mul(sm2_data->group, sm2_data->pkey, sm2_data->da, NULL, NULL,
                      NULL)) {
      strcpy(sm2_data->error, "unknown error");
      break;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(sm2_data->group)) ==
        NID_X9_62_prime_field) {
      if (!EC_POINT_get_affine_coordinates_GFp(sm2_data->group, sm2_data->pkey,
                                               x, y, ctx)) {
        strcpy(sm2_data->error, "unknown error");
        break;
      }
    } else {
      if (!EC_POINT_get_affine_coordinates_GF2m(sm2_data->group, sm2_data->pkey,
                                                x, y, ctx)) {
        strcpy(sm2_data->error, "unknown error");
        break;
      }
    }
    // The first version of the national standard requires that the first byte
    // of the X, Y coordinate of the public key cannot be 0. if
    // (BN_num_bytes(order) > BN_num_bytes(x) || BN_num_bytes(order) >
    // BN_num_bytes(y)) { 	error_ = "SM2 rule: the first byte of publickey
    // can
    // not be zero"; 	break;
    // }
    sm2_data->valid = true;
  } while (false);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  return sm2_data->valid;
}

bool new_random(SM2_DATA *sm2_data) {
  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  BIGNUM *x = BN_CTX_get(ctx);
  BIGNUM *y = BN_CTX_get(ctx);
  BIGNUM *order = BN_CTX_get(ctx);
  EC_GROUP_get_order(sm2_data->group, order, ctx);

  do {
    if (!BN_rand_range(sm2_data->da, order)) {
      continue;
    }
    if (BN_cmp(sm2_data->da, order) == 0) {
      continue;
    }
    if (!EC_POINT_mul(sm2_data->group, sm2_data->pkey, sm2_data->da, NULL, NULL,
                      NULL))
      continue;

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(sm2_data->group)) ==
        NID_X9_62_prime_field) {
      if (!EC_POINT_get_affine_coordinates_GFp(sm2_data->group, sm2_data->pkey,
                                               x, y, ctx)) {
        continue;
      }
    } else {
      if (!EC_POINT_get_affine_coordinates_GF2m(sm2_data->group, sm2_data->pkey,
                                                x, y, ctx)) {
        continue;
      }
    }

    // The first version of the national standard requires that the first byte
    // of the X, Y coordinate of the public key cannot be 0.
    if (BN_num_bytes(order) != BN_num_bytes(x) ||
        BN_num_bytes(order) != BN_num_bytes(y)) {
      continue;
    }
    break;
  } while (true);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  sm2_data->valid = true;
  return sm2_data->valid;
}

char *get_skey_bin(struct BIGNUM *da, int *out_len) {
  return bn2_fixed_string(da, 32, out_len);
}

char *sign_sm2(const char *id, const char *msg, int msg_len, SM2_DATA sm2_data,
               int *out_len) {
  char *sigr = (char *)malloc(256);
  memset(sigr, 0, 256);
  char sigs[256] = {0};
  int olen = 0;
  if (!sm2_data.valid) {
    return NULL;
  }
  bool ok = false;

  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  EC_POINT *pt1 = EC_POINT_new(sm2_data.group);
  // char m[256] = {0};
  char stre[33] = {0};
  char za[256] = {0};
  int dgstlen;
  unsigned char dgst[33];
  BIGNUM *r = BN_CTX_get(ctx);
  BIGNUM *s = BN_CTX_get(ctx);
  BIGNUM *e = BN_CTX_get(ctx);
  BIGNUM *bn = BN_CTX_get(ctx);
  BIGNUM *k = BN_CTX_get(ctx);
  BIGNUM *x1 = BN_CTX_get(ctx);
  BIGNUM *order = BN_CTX_get(ctx);
  BIGNUM *p = BN_CTX_get(ctx);

  if (!sm2_data.group || !sm2_data.da) {
    goto end;
  }

  if (!r || !s || !ctx || !order || !e || !bn) {
    goto end;
  }
  EC_GROUP_get_order(sm2_data.group, order, ctx);
  EC_GROUP_get_curve_GFp(sm2_data.group, p, NULL, NULL, ctx);

  // Step 1  M^ = ZA||M
  char *za_temp = get_za(sm2_data.group, id, sm2_data.pkey);
  int za_len = 32;
  memcpy(za, za_temp, za_len);
  if (za_temp) {
    free(za_temp);
    za_temp = NULL;
  }
  // za[za_len] = '\0';
  memcpy(za + za_len, msg, msg_len);
  int final_len = za_len + msg_len;
  za[final_len] = '\0';
  // Step 2 e=Hv(M^)
  sm3_crypto(za, final_len, stre);

  dgstlen = 32;
  memcpy(dgst, stre, dgstlen);
  dgst[dgstlen] = '\0';
  if (!BN_bin2bn(dgst, dgstlen, e)) {
    goto end;
  }

  do {
    // Step 3  generate random k [1,n-1]
    do {
      do {
        if (!BN_rand_range(k, order)) {
          goto end;
        }
      } while (BN_is_zero(k) || (BN_ucmp(k, order) == 0));

      // Step 4  calculate node G pt1(x1,y1) = [K]
      if (!EC_POINT_mul(sm2_data.group, pt1, k, NULL, NULL, ctx)) {
        goto end;
      }

      // Obtain the coordinate for pt1
      if (EC_METHOD_get_field_type(EC_GROUP_method_of(sm2_data.group)) ==
          NID_X9_62_prime_field) {
        if (!EC_POINT_get_affine_coordinates_GFp(sm2_data.group, pt1, x1, NULL,
                                                 ctx)) {
          goto end;
        }
      } else /* NID_X9_62_characteristic_two_field */ {
        if (!EC_POINT_get_affine_coordinates_GF2m(sm2_data.group, pt1, x1, NULL,
                                                  ctx)) {
          goto end;
        }
      }

      if (!BN_nnmod(x1, x1, order, ctx)) {
        goto end;
      }

    } while (BN_is_zero(x1));

    // Step 5  calculate r = (e + x1) mod n
    BN_copy(r, x1);
    if (!BN_mod_add(r, r, e, order, ctx)) {
      goto end;
    }

    if (!BN_mod_add(bn, r, k, order, ctx)) {
      goto end;
    }

    // Ensure r!=0 and r+k!=n namely (r+k) != 0 mod n
    if (BN_is_zero(r) || BN_is_zero(bn)) {
      continue;
    }

    // Step 6  calculate s = ((1 + d)^-1 * (k - rd)) mod n
    if (!BN_one(bn)) {
      goto end;
    }

    if (!BN_mod_add(s, sm2_data.da, bn, order, ctx)) {
      goto end;
    }
    if (!BN_mod_inverse(s, s, order, ctx)) {
      goto end;
    }

    if (!BN_mod_mul(bn, r, sm2_data.da, order, ctx)) {
      goto end;
    }
    if (!BN_mod_sub(bn, k, bn, order, ctx)) {
      goto end;
    }
    if (!BN_mod_mul(s, s, bn, order, ctx)) {
      goto end;
    }

    // Ensure s != 0
    if (!BN_is_zero(s)) {
      break;
    }
    // Step seven Output r and s
  } while (1);

  ok = true;
end:

  BN_num_bytes(p);
  char *sigr_temp = bn2_fixed_string(r, 32, &olen);
  int sigr_temp_len = olen;
  olen = 0;
  char *sigs_temp = bn2_fixed_string(s, 32, &olen);
  int sigs_temp_len = olen;

  memcpy(sigr, sigr_temp, sigr_temp_len);
  memcpy(sigs, sigs_temp, sigs_temp_len);
  if (sigr_temp)
    free(sigr_temp);
  if (sigs_temp)
    free(sigs_temp);
  free_ec_point(pt1);
  BN_CTX_free(ctx);
  // strcat(sigr, sigs);
  memcpy(sigr + sigr_temp_len, sigs, sigs_temp_len);
  int sigr_len = sigr_temp_len + sigs_temp_len;
  sigr[sigr_len] = '\0';
  *out_len = sigr_len;
  return sigr;
}

int verify_sm2(struct EC_GROUP *group, const char *pkey, int pkey_len,
               const char *id, const char *msg, const char *strsig,
               int sig_len) {
  char px[128] = {0};
  char py[128] = {0};
  int len = (pkey_len - 1) / 2;
  memcpy(px, pkey + 1, len);
  memcpy(py, pkey + 1 + len, len);
  px[len] = '\0';
  py[len] = '\0';

  char sigr[256] = {0};
  char sigs[256] = {0};
  int sig_temp_len = sig_len / 2;
  memcpy(sigr, strsig, sig_temp_len);
  memcpy(sigs, strsig + sig_temp_len, sig_temp_len);
  sigr[sig_temp_len] = '\0';
  sigs[sig_temp_len] = '\0';

  int ret = -1;
  EC_POINT *pub_key = NULL;
  EC_POINT *point = NULL;
  BN_CTX *ctx = NULL;

  char m[128] = {0};
  char za[128] = {0};
  char stre[128] = {0};

  pub_key = EC_POINT_new(group);
  point = EC_POINT_new(group);
  unsigned char dgst[33];
  int dgstlen;

  ctx = BN_CTX_new();
  BN_CTX_start(ctx);

  BIGNUM *xp = BN_CTX_get(ctx);
  BIGNUM *yp = BN_CTX_get(ctx);
  BIGNUM *x1 = BN_CTX_get(ctx);
  BIGNUM *R = BN_CTX_get(ctx);
  BIGNUM *order = BN_CTX_get(ctx);
  BIGNUM *e = BN_CTX_get(ctx);
  BIGNUM *t = BN_CTX_get(ctx);

  EC_GROUP_get_order(group, order, ctx);
  BN_bin2bn((const unsigned char *)px, len, xp);
  BN_bin2bn((const unsigned char *)py, len, yp);
  if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
      NID_X9_62_prime_field) {
    EC_POINT_set_affine_coordinates_GFp(group, pub_key, xp, yp, NULL);
  } else {
    EC_POINT_set_affine_coordinates_GF2m(group, pub_key, xp, yp, NULL);
  }

  BIGNUM *r = BN_CTX_get(ctx);
  BIGNUM *s = BN_CTX_get(ctx);
  BN_bin2bn((const unsigned char *)sigr, sig_temp_len, r);
  BN_bin2bn((const unsigned char *)sigs, sig_temp_len, s);

  e = BN_CTX_get(ctx);
  t = BN_CTX_get(ctx);
  if (!ctx || !order || !e || !t) {
    goto end;
  }

  // Step 1 and 2: r, s are in the range of [1, n-1] and r + s != 0 (mod n)
  if (BN_is_zero(r) || BN_is_negative(r) || BN_ucmp(r, order) >= 0 ||
      BN_is_zero(s) || BN_is_negative(s) || BN_ucmp(s, order) >= 0) {
    ret = 0;
    goto end;
  }

  // Step 5  (r' + s') != 0 mod n
  if (!BN_mod_add(t, r, s, order, ctx)) {
    goto end;
  }
  if (BN_is_zero(t)) {
    ret = 0;
    goto end;
  }

  // Step 3  Calculate _M = ZA||M'
  char *za_temp = get_za(group, id, pub_key);
  memcpy(za, za_temp, 32);
  memcpy(za + 32, msg, strlen(msg));
  int za_len = 32 + strlen(msg);
  za[za_len] = '\0';
  if (za_temp)
    free(za_temp);
  // Step 4  calculate e' = Hv(_M)
  sm3_crypto(za, za_len, stre);

  memcpy(dgst, stre, 32);
  dgstlen = 32;
  dgst[dgstlen] = '\0';
  if (!BN_bin2bn(dgst, dgstlen, e)) {
    goto end;
  }

  // Step 6 calculate point (x',y')=sG + tP  P is public key point

  if (!EC_POINT_mul(group, point, s, pub_key, t, ctx)) {
    goto end;
  }
  if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
      NID_X9_62_prime_field) {
    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x1, NULL, ctx)) {
      goto end;
    }
  } else /* NID_X9_62_characteristic_two_field */ {
    if (!EC_POINT_get_affine_coordinates_GF2m(group, point, x1, NULL, ctx)) {
      goto end;
    }
  }
  if (!BN_nnmod(x1, x1, order, ctx)) {
    goto end;
  }

  // Step 7  R=(e+x') mod n

  if (!BN_mod_add(R, x1, e, order, ctx)) {
    goto end;
  }

  BN_nnmod(R, R, order, ctx);

  if (BN_ucmp(R, r) == 0) {
    ret = 1;
  } else {
    // printf("%s:%s\n", BN_bn2hex(R), BN_bn2hex(sig->r));
    // printf("ZA=%s\n", utils::String::BinToHexString(ZA).c_str());
    // printf("e=%s\n", utils::String::BinToHexString(stre).c_str());
    ret = 0;
  }

end:
  free_ec_point(point);
  free_ec_point(pub_key);

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  if (ret != 1) {
    int x = 2;
  }

  return ret;
}

char *get_public_key_sm2(SM2_DATA sm2_data, int *out_len) {
  char xpa[128] = {0};
  char ypa[128] = {0};
  if (!sm2_data.valid) {
    return NULL;
  }
  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  BIGNUM *bn_x = BN_CTX_get(ctx);
  BIGNUM *bn_y = BN_CTX_get(ctx);

  if (EC_METHOD_get_field_type(EC_GROUP_method_of(sm2_data.group)) ==
      NID_X9_62_prime_field)
    EC_POINT_get_affine_coordinates_GFp(sm2_data.group, sm2_data.pkey, bn_x,
                                        bn_y, NULL);
  else
    EC_POINT_get_affine_coordinates_GF2m(sm2_data.group, sm2_data.pkey, bn_x,
                                         bn_y, NULL);

  // unsigned char xx[MAX_BITS];
  BIGNUM *order = BN_CTX_get(ctx);
  EC_GROUP_get_order(sm2_data.group, order, ctx);

  BIGNUM *p = BN_CTX_get(ctx);
  EC_GROUP_get_curve_GFp(sm2_data.group, p, NULL, NULL, ctx);
  int olen = BN_num_bytes(p);

  int xpa_len = 0;
  int ypa_len = 0;
  char *xpa_temp = bn2_fixed_string(bn_x, 32, &xpa_len);
  char *ypa_temp = bn2_fixed_string(bn_y, 32, &ypa_len);
  memcpy(xpa, xpa_temp, 32);
  memcpy(ypa, ypa_temp, 32);
  xpa[32] = '\0';
  ypa[32] = '\0';

  if (xpa_temp)
    free(xpa_temp);
  if (ypa_temp)
    free(ypa_temp);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  char *out = (char *)malloc(256);
  memset(out, 0, 256);
  out[0] = 0x04;
  memcpy(out + 1, xpa, 32);
  // out[33] = '\0';
  memcpy(out + 33, ypa, 32);
  *out_len = 32 + 33;
  out[*out_len] = '\0';

  return out;
}

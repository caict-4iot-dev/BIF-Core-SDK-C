/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __BIP32_H__
#define __BIP32_H__

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "ecdsa.h"
#include "options.h"

typedef struct {
	const char *bip32_name;    // string for generating BIP32 xprv from seed
	const ecdsa_curve *params; // ecdsa curve parameters, null for ed25519

	HasherType hasher_base58;
	HasherType hasher_sign;
	HasherType hasher_pubkey;
	HasherType hasher_script;
} curve_info;

typedef struct {
	uint32_t depth;
	uint32_t child_num;
	uint8_t chain_code[32];

	uint8_t private_key[32];
	uint8_t private_key_extension[32];

	uint8_t public_key[33];
	const curve_info *curve;
} HDNode;

int hdnode_from_seed(const uint8_t *seed, int seed_len, const char *curve, HDNode *out);

#define hdnode_private_ckd_prime(X, I) hdnode_private_ckd((X), ((I) | 0x80000000))

int hdnode_private_ckd(HDNode *inout, uint32_t i);

int hdnode_public_ckd_cp(const ecdsa_curve *curve, const curve_point *parent, const uint8_t *parent_chain_code, uint32_t i, curve_point *child, uint8_t *child_chain_code);

int hdnode_public_ckd(HDNode *inout, uint32_t i);

uint32_t hdnode_fingerprint(HDNode *node);

void hdnode_fill_public_key(HDNode *node);


int hdnode_sign(HDNode *node, const uint8_t *msg, uint32_t msg_len, HasherType hasher_sign, uint8_t *sig, uint8_t *pby, int (*is_canonical)(uint8_t by, uint8_t sig[64]));
int hdnode_sign_digest(HDNode *node, const uint8_t *digest, uint8_t *sig, uint8_t *pby, int (*is_canonical)(uint8_t by, uint8_t sig[64]));

int hdnode_serialize_public(const HDNode *node, uint32_t fingerprint, uint32_t version, char *str, int strsize);

int hdnode_serialize_private(const HDNode *node, uint32_t fingerprint, uint32_t version, char *str, int strsize);

const curve_info *get_curve_by_name(const char *curve_name);

#endif

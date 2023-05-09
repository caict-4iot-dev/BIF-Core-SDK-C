/**
 * Copyright (c) 2013-2016 Tomas Dzetkulic
 * Copyright (c) 2013-2016 Pavol Rusnak
 * Copyright (c) 2015-2016 Jochen Hoenicke
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

#include <string.h>
#include <stdbool.h>
#include "mnemonic/bignum.h"
#include "mnemonic/hmac.h"
#include "mnemonic/ecdsa.h"
#include "mnemonic/bip32.h"
#include "mnemonic/sha2.h"
#include "mnemonic/sha3.h"
#include "mnemonic/base58.h"
#include "mnemonic/curves.h"
#include "mnemonic/secp256k1.h"
#include "mnemonic/nist256p1.h"
#if USE_CARDANO
#include "mnemonic/pbkdf2.h"
#endif
#include "util.h"

int hdnode_from_seed(const uint8_t *seed, int seed_len, const char* curve, HDNode *out)
{
	static CONFIDENTIAL uint8_t I[32 + 32];
	memset(out, 0, sizeof(HDNode));
	out->depth = 0;
	out->child_num = 0;
	out->curve = get_curve_by_name(curve);
	if (out->curve == 0) {
		return 0;
	}
	static CONFIDENTIAL HMAC_SHA512_CTX ctx;
	hmac_sha512_Init(&ctx, (const uint8_t*) out->curve->bip32_name, strlen(out->curve->bip32_name));
	hmac_sha512_Update(&ctx, seed, seed_len);
	hmac_sha512_Final(&ctx, I);

	if (out->curve->params) {
		bignum256 a;
		while (true) {
			bn_read_be(I, &a);
			if (!bn_is_zero(&a) // != 0
				&& bn_is_less(&a, &out->curve->params->order)) { // < order
				break;
			}
			hmac_sha512_Init(&ctx, (const uint8_t*) out->curve->bip32_name, strlen(out->curve->bip32_name));
			hmac_sha512_Update(&ctx, I, sizeof(I));
			hmac_sha512_Final(&ctx, I);
		}
		memzero(&a, sizeof(a));
	}
	memcpy(out->private_key, I, 32);
	memcpy(out->chain_code, I + 32, 32);
	memzero(out->public_key, sizeof(out->public_key));
	memzero(I, sizeof(I));
	return 1;
}

uint32_t hdnode_fingerprint(HDNode *node)
{
	uint8_t digest[32];
	uint32_t fingerprint;

	hdnode_fill_public_key(node);
	hasher_Raw(node->curve->hasher_pubkey, node->public_key, 33, digest);
	fingerprint = ((uint32_t) digest[0] << 24) + (digest[1] << 16) + (digest[2] << 8) + digest[3];
	memzero(digest, sizeof(digest));
	return fingerprint;
}

int hdnode_private_ckd(HDNode *inout, uint32_t i)
{
	static CONFIDENTIAL uint8_t data[1 + 32 + 4];
	static CONFIDENTIAL uint8_t I[32 + 32];
	static CONFIDENTIAL bignum256 a, b;

	if (i & 0x80000000) { // private derivation
		data[0] = 0;
		memcpy(data + 1, inout->private_key, 32);
	} else { // public derivation
		if (!inout->curve->params) {
			return 0;
		}
		hdnode_fill_public_key(inout);
		memcpy(data, inout->public_key, 33);
	}
	write_be(data + 33, i);

	bn_read_be(inout->private_key, &a);

	static CONFIDENTIAL HMAC_SHA512_CTX ctx;
	hmac_sha512_Init(&ctx, inout->chain_code, 32);
	hmac_sha512_Update(&ctx, data, sizeof(data));
	hmac_sha512_Final(&ctx, I);

	if (inout->curve->params) {
		while (true) {
			bool failed = false;
			bn_read_be(I, &b);
			if (!bn_is_less(&b, &inout->curve->params->order)) { // >= order
				failed = true;
			} else {
				bn_add(&b, &a);
				bn_mod(&b, &inout->curve->params->order);
				if (bn_is_zero(&b)) {
					failed = true;
				}
			}

			if (!failed) {
				bn_write_be(&b, inout->private_key);
				break;
			}

			data[0] = 1;
			memcpy(data + 1, I + 32, 32);
			hmac_sha512_Init(&ctx, inout->chain_code, 32);
			hmac_sha512_Update(&ctx, data, sizeof(data));
			hmac_sha512_Final(&ctx, I);
		}
	} else {
		memcpy(inout->private_key, I, 32);
	}

	memcpy(inout->chain_code, I + 32, 32);
	inout->depth++;
	inout->child_num = i;
	memzero(inout->public_key, sizeof(inout->public_key));

	// making sure to wipe our memory
	memzero(&a, sizeof(a));
	memzero(&b, sizeof(b));
	memzero(I, sizeof(I));
	memzero(data, sizeof(data));
	return 1;
}

int hdnode_public_ckd_cp(const ecdsa_curve *curve, const curve_point *parent, const uint8_t *parent_chain_code, uint32_t i, curve_point *child, uint8_t *child_chain_code) {
	uint8_t data[1 + 32 + 4];
	uint8_t I[32 + 32];
	bignum256 c;

	if (i & 0x80000000) { // private derivation
		return 0;
	}

	data[0] = 0x02 | (parent->y.val[0] & 0x01);
	bn_write_be(&parent->x, data + 1);
	write_be(data + 33, i);

	while (true) {
		hmac_sha512(parent_chain_code, 32, data, sizeof(data), I);
		bn_read_be(I, &c);
		if (bn_is_less(&c, &curve->order)) { // < order
			scalar_multiply(curve, &c, child); // b = c * G
			point_add(curve, parent, child);   // b = a + b
			if (!point_is_infinity(child)) {
				if (child_chain_code) {
					memcpy(child_chain_code, I + 32, 32);
				}

				// Wipe all stack data.
				memzero(data, sizeof(data));
				memzero(I, sizeof(I));
				memzero(&c, sizeof(c));
				return 1;
			}
		}

		data[0] = 1;
		memcpy(data + 1, I + 32, 32);
	}
}

int hdnode_public_ckd(HDNode *inout, uint32_t i)
{
	curve_point parent, child;

	if (!ecdsa_read_pubkey(inout->curve->params, inout->public_key, &parent)) {
		return 0;
	}
	if (!hdnode_public_ckd_cp(inout->curve->params, &parent, inout->chain_code, i, &child, inout->chain_code)) {
		return 0;
	}
	memzero(inout->private_key, 32);
	inout->depth++;
	inout->child_num = i;
	inout->public_key[0] = 0x02 | (child.y.val[0] & 0x01);
	bn_write_be(&child.x, inout->public_key + 1);

	// Wipe all stack data.
	memzero(&parent, sizeof(parent));
	memzero(&child, sizeof(child));

	return 1;
}

void hdnode_fill_public_key(HDNode *node)
{
	if (node->public_key[0] != 0)
		return;

	ecdsa_get_public_key33(node->curve->params, node->private_key, node->public_key);
}

// msg is a data to be signed
// msg_len is the message length
int hdnode_sign(HDNode *node, const uint8_t *msg, uint32_t msg_len, HasherType hasher_sign, uint8_t *sig, uint8_t *pby, int (*is_canonical)(uint8_t by, uint8_t sig[64]))
{
	if (node->curve->params) {
		return ecdsa_sign(node->curve->params, hasher_sign, node->private_key, msg, msg_len, sig, pby, is_canonical);
	}else {
		hdnode_fill_public_key(node);
		return 0;
	}
}

int hdnode_sign_digest(HDNode *node, const uint8_t *digest, uint8_t *sig, uint8_t *pby, int (*is_canonical)(uint8_t by, uint8_t sig[64]))
{
	if (node->curve->params) {
		return ecdsa_sign_digest(node->curve->params, node->private_key, digest, sig, pby, is_canonical);
	}else {
		return hdnode_sign(node, digest, 32, 0, sig, pby, is_canonical);
	}
}

static int hdnode_serialize(const HDNode *node, uint32_t fingerprint, uint32_t version, char use_public, char *str, int strsize)
{
	uint8_t node_data[78];
	write_be(node_data, version);
	node_data[4] = node->depth;
	write_be(node_data + 5, fingerprint);
	write_be(node_data + 9, node->child_num);
	memcpy(node_data + 13, node->chain_code, 32);
	if (use_public) {
		memcpy(node_data + 45, node->public_key, 33);
	} else {
		node_data[45] = 0;
		memcpy(node_data + 46, node->private_key, 32);
	}
	int ret = base58_encode_check(node_data, sizeof(node_data), node->curve->hasher_base58, str, strsize);
	memzero(node_data, sizeof(node_data));
	return ret;
}

int hdnode_serialize_public(const HDNode *node, uint32_t fingerprint, uint32_t version, char *str, int strsize)
{
	return hdnode_serialize(node, fingerprint, version, 1, str, strsize);
}

int hdnode_serialize_private(const HDNode *node, uint32_t fingerprint, uint32_t version, char *str, int strsize)
{
	return hdnode_serialize(node, fingerprint, version, 0, str, strsize);
}

const curve_info *get_curve_by_name(const char *curve_name) {
	if (curve_name == 0) {
		return 0;
	}
	if (strcmp(curve_name, SECP256K1_NAME) == 0) {
		return &secp256k1_info;
	}
	if (strcmp(curve_name, SECP256K1_DECRED_NAME) == 0) {
		return &secp256k1_decred_info;
	}
	if (strcmp(curve_name, SECP256K1_GROESTL_NAME) == 0) {
		return &secp256k1_groestl_info;
	}
	if (strcmp(curve_name, SECP256K1_SMART_NAME) == 0) {
		return &secp256k1_smart_info;
	}
	if (strcmp(curve_name, NIST256P1_NAME) == 0) {
		return &nist256p1_info;
	}

	return 0;
}

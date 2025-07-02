/*******************************************************************************
 *   (c) 2018 - 2023 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "crypto.h"

#include <stdio.h>

#include "base32.h"
#include "coin.h"
#include "coin_evm.h"
#include "cx.h"
#include "cx_blake2b.h"
#include "tx.h"
#include "zxformat.h"
#include "zxmacros.h"

static cx_blake2b_t *ctx_blake2b = NULL;

static zxerr_t crypto_extractPublicKey(uint8_t *pubKey, uint16_t pubKeyLen, uint8_t *chainCode) {
    if (pubKey == NULL || pubKeyLen < SECP256K1_PK_LEN) {
        return zxerr_invalid_crypto_settings;
    }

    cx_ecfp_public_key_t cx_publicKey = {0};
    cx_ecfp_private_key_t cx_privateKey = {0};
    uint8_t privateKeyData[SECP256K1_SK_LEN] = {0};

    zxerr_t error = zxerr_unknown;
    // Generate keys
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_256K1, hdPath, hdPath_len, privateKeyData,
                                                     chainCode, NULL, 0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_256K1, NULL, 0, &cx_publicKey));
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1));
    memcpy(pubKey, cx_publicKey.W, SECP256K1_PK_LEN);
    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(pubKey, pubKeyLen);
    }

    return error;
}

__Z_INLINE zxerr_t keccak_hash(const unsigned char *in, unsigned int inLen, unsigned char *out, unsigned int outLen) {
    // return actual size using value from signatureLength
    cx_sha3_t keccak;
    if (cx_keccak_init_no_throw(&keccak, outLen * 8) != CX_OK) return zxerr_unknown;
    CHECK_CX_OK(cx_hash_no_throw((cx_hash_t *)&keccak, CX_LAST, in, inLen, out, outLen));

    return zxerr_ok;
}

zxerr_t keccak_digest(const unsigned char *in, unsigned int inLen, unsigned char *out, unsigned int outLen) {
    return keccak_hash(in, inLen, out, outLen);
}
zxerr_t blake_hash_setup(cx_blake2b_t *hasher) {
    if (hasher == NULL) {
        return zxerr_no_data;
    }
    ctx_blake2b = hasher;
    return zxerr_ok;
}

zxerr_t blake_hash_init() {
    if (ctx_blake2b == NULL || cx_blake2b_init_no_throw(ctx_blake2b, BLAKE2B_256_SIZE * 8) != CX_OK) {
        return zxerr_unknown;
    }
    return zxerr_ok;
}

zxerr_t blake_hash_update(const uint8_t *in, uint16_t inLen) {
    if (in == NULL || ctx_blake2b == NULL) {
        return zxerr_no_data;
    }

    if (cx_blake2b_update(ctx_blake2b, in, inLen) != CX_OK) {
        return zxerr_unknown;
    }

    return zxerr_ok;
}

zxerr_t blake_hash_finish(uint8_t *out, uint16_t outLen) {
    if (out == NULL || outLen < BLAKE2B_256_SIZE || ctx_blake2b == NULL) {
        return zxerr_no_data;
    }
    cx_blake2b_final(ctx_blake2b, out);
    return zxerr_ok;
}

zxerr_t blake_hash(const uint8_t *in, uint16_t inLen, uint8_t *out, uint16_t outLen) {
    if (in == NULL || inLen == 0 || out == NULL) {
        return zxerr_unknown;
    }
    cx_blake2b_t ctx;
    if (cx_blake2b_init_no_throw(&ctx, outLen * 8) != CX_OK) return zxerr_unknown;
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, in, inLen, out, outLen));

    return zxerr_ok;
}

zxerr_t blake_hash_cid(const unsigned char *in, unsigned int inLen, unsigned char *out, unsigned int outLen) {
    uint8_t prefix[] = PREFIX;

    cx_blake2b_t ctx;
    if (cx_blake2b_init_no_throw(&ctx, outLen * 8) != CX_OK) return zxerr_unknown;
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, prefix, sizeof(prefix), NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, in, inLen, out, outLen));

    return zxerr_ok;
}

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) signature_t;

zxerr_t _sign(uint8_t *output, uint16_t outputLen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize,
              unsigned int *info) {
    if (output == NULL || message == NULL || sigSize == NULL || outputLen < sizeof(signature_t) ||
        messageLen != CX_SHA256_SIZE) {
        return zxerr_invalid_crypto_settings;
    }

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SECP256K1_SK_LEN] = {0};
    size_t signatureLength = sizeof_field(signature_t, der_signature);
    uint32_t tmpInfo = 0;
    *sigSize = 0;

    signature_t *const signature = (signature_t *)output;
    zxerr_t error = zxerr_unknown;

    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_256K1, hdPath, hdPath_len, privateKeyData,
                                                     NULL, NULL, 0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecdsa_sign_no_throw(&cx_privateKey, CX_RND_RFC6979 | CX_LAST, CX_SHA256, message, messageLen,
                                         signature->der_signature, &signatureLength, &tmpInfo));

    const err_convert_e err_c =
        convertDERtoRSV(signature->der_signature, tmpInfo, signature->r, signature->s, &signature->v);
    if (err_c == no_error) {
        *sigSize = sizeof_field(signature_t, r) + sizeof_field(signature_t, s) + sizeof_field(signature_t, v) +
                   signatureLength;
        if (info != NULL) *info = tmpInfo;
        error = zxerr_ok;
    }

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(output, outputLen);
    }

    return error;
}

// Sign a filecoin related transaction
zxerr_t crypto_sign(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen,
                    uint16_t *sigSize) {
    if (buffer == NULL || message == NULL || sigSize == NULL || signatureMaxlen < sizeof(signature_t)) {
        return zxerr_invalid_crypto_settings;
    }

    uint8_t tmp[BLAKE2B_256_SIZE] = {0};
    uint8_t message_digest[BLAKE2B_256_SIZE] = {0};

    blake_hash(message, messageLen, tmp, BLAKE2B_256_SIZE);
    CHECK_ZXERR(blake_hash_cid(tmp, BLAKE2B_256_SIZE, message_digest, BLAKE2B_256_SIZE))

    return _sign(buffer, signatureMaxlen, message_digest, BLAKE2B_256_SIZE, sigSize, NULL);
}

zxerr_t crypto_sign_raw_bytes(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *digest, uint16_t messageLen,
                              uint16_t *sigSize) {
    if (buffer == NULL || digest == NULL || sigSize == NULL || signatureMaxlen < sizeof(signature_t)) {
        return zxerr_invalid_crypto_settings;
    }

    if (messageLen != BLAKE2B_256_SIZE) return zxerr_invalid_crypto_settings;

    return _sign(buffer, signatureMaxlen, digest, BLAKE2B_256_SIZE, sigSize, NULL);
}

// Sign an ethereum related transaction
zxerr_t crypto_sign_eth(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen,
                        uint16_t *sigSize) {
    if (buffer == NULL || message == NULL || sigSize == NULL || signatureMaxlen < sizeof(signature_t)) {
        return zxerr_invalid_crypto_settings;
    }

    uint8_t message_digest[KECCAK_256_SIZE] = {0};
    CHECK_ZXERR(keccak_digest(message, messageLen, message_digest, KECCAK_256_SIZE))

    unsigned int info = 0;
    zxerr_t error = _sign(buffer, signatureMaxlen, message_digest, KECCAK_256_SIZE, sigSize, &info);
    if (error != zxerr_ok) {
        return zxerr_invalid_crypto_settings;
    }

    // we need to fix V
    uint8_t v = 0;
    error = tx_compute_eth_v(info, &v);

    if (error != zxerr_ok) return zxerr_invalid_crypto_settings;

    // need to reorder signature as hw-eth-app expects v at the beginning.
    // so rsv -> vrs
    uint8_t rs_size = sizeof_field(signature_t, r) + sizeof_field(signature_t, s);
    memmove(buffer + 1, buffer, rs_size);
    buffer[0] = v;

    return error;
}

typedef struct {
    uint8_t publicKey[SECP256K1_PK_LEN];

    // payload as described in https://filecoin-projectegithub.io/specs/#protocol-1-libsecpk1-elliptic-curve-public-keys
    // payload [prot][hashed(pk)]       // 1 + 20
    uint8_t addrBytesLen;
    uint8_t addrBytes[21];

    uint8_t addrStrLen;
    uint8_t addrStr[41];

} __attribute__((packed)) answer_t;

typedef struct {
    // plus 1-bytes to write pubkey len
    uint8_t publicKey[SECP256K1_PK_LEN + 1];
    // hex of the ethereum address plus 1-bytes
    // to write the address len
    uint8_t address[(ETH_ADDR_LEN * 2) + 1];
    // place holder for further dev
    uint8_t chainCode[32];

} __attribute__((packed)) answer_eth_t;

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    if (buffer == NULL || buffer_len < sizeof(answer_t) || addrLen == NULL) {
        return zxerr_no_data;
    }
    MEMZERO(buffer, buffer_len);
    answer_t *const answer = (answer_t *)buffer;

    CHECK_ZXERR(crypto_extractPublicKey(answer->publicKey, sizeof_field(answer_t, publicKey), NULL))

    // addr bytes
    answer->addrBytesLen = sizeof_field(answer_t, addrBytes);
    answer->addrBytes[0] = ADDRESS_PROTOCOL_SECP256K1;
    blake_hash(answer->publicKey, SECP256K1_PK_LEN, answer->addrBytes + 1, answer->addrBytesLen - 1);

    // addr str
    answer->addrStrLen = sizeof_field(answer_t, addrStr);
    *addrLen = formatProtocol(answer->addrBytes, answer->addrBytesLen, answer->addrStr, answer->addrStrLen);

    if (*addrLen != answer->addrStrLen) {
        return zxerr_encoding_failed;
    }

    *addrLen = sizeof(answer_t);
    return zxerr_ok;
}

zxerr_t crypto_fillEthAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    if (buffer == NULL || buffer_len < sizeof(answer_eth_t) || addrLen == NULL) {
        return zxerr_no_data;
    }
    MEMZERO(buffer, buffer_len);
    answer_eth_t *const answer = (answer_eth_t *)buffer;

    CHECK_ZXERR(
        crypto_extractPublicKey(&answer->publicKey[1], sizeof_field(answer_eth_t, publicKey) - 1, &fil_chain_code))

    answer->publicKey[0] = SECP256K1_PK_LEN;

    uint8_t hash[KECCAK_256_SIZE] = {0};

    CHECK_ZXERR(keccak_digest(&answer->publicKey[2], SECP256K1_PK_LEN - 1, hash, KECCAK_256_SIZE))

    answer->address[0] = ETH_ADDR_LEN * 2;

    // get hex of the eth address(last 20 bytes of pubkey hash)
    char str[41] = {0};

    // take the last 20-bytes of the hash, they are the ethereum address
    array_to_hexstr(str, 41, hash + 12, ETH_ADDR_LEN);
    MEMCPY(answer->address + 1, str, 40);

    *addrLen = sizeof_field(answer_eth_t, publicKey) + sizeof_field(answer_eth_t, address);

    return zxerr_ok;
}

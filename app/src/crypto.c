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
#include "coin.h"
#include "tx.h"
#include "zxmacros.h"
#include "base32.h"
#include "zxformat.h"

#include "cx.h"
#include "cx_blake2b.h"

static cx_blake2b_t *ctx_blake2b = NULL;

zxerr_t crypto_extractPublicKey(const uint32_t path[MAX_BIP32_PATH], uint8_t *pubKey, uint16_t pubKeyLen, uint8_t *chainCode) {

    cx_ecfp_public_key_t cx_publicKey = {0};
    cx_ecfp_private_key_t cx_privateKey = {0};
    uint8_t privateKeyData[32] = {0};

    if (pubKeyLen < SECP256K1_PK_LEN) {
        return zxerr_invalid_crypto_settings;
    }

    volatile zxerr_t error = zxerr_unknown;
    BEGIN_TRY
    {
        TRY {
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       hdPath_len,
                                       privateKeyData, chainCode );

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);
            cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey);
            cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1);
            error = zxerr_ok;
        }
        CATCH_OTHER(e) {
            error = zxerr_ledger_api_error;
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    if (error != zxerr_ok) {
        return error;
    }

    memcpy(pubKey, cx_publicKey.W, SECP256K1_PK_LEN);
    return zxerr_ok;
}

__Z_INLINE int keccak_hash(const unsigned char *in, unsigned int inLen,
                          unsigned char *out, unsigned int outLen) {
    // return actual size using value from signatureLength
    cx_sha3_t keccak;
    cx_keccak_init(&keccak, outLen * 8);
    cx_hash((cx_hash_t *)&keccak, CX_LAST, in, inLen, out, outLen);

    return 0;
}

int keccak_digest(const unsigned char *in, unsigned int inLen,
                          unsigned char *out, unsigned int outLen) {
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
    cx_blake2b_init(&ctx, outLen * 8);
    cx_hash(&ctx.header, CX_LAST, in, inLen, out, outLen);

    return zxerr_ok;
}

int blake_hash_cid(const unsigned char *in, unsigned int inLen,
               unsigned char *out, unsigned int outLen) {

    uint8_t prefix[] = PREFIX;

    cx_blake2b_t ctx;
    cx_blake2b_init(&ctx, outLen * 8);
    cx_hash(&ctx.header, 0, prefix, sizeof(prefix), NULL, 0);
    cx_hash(&ctx.header, CX_LAST, in, inLen, out, outLen);

    return 0;
}

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) signature_t;

unsigned int info = 0;


zxerr_t _sign(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize, const uint32_t *path, uint32_t pathLen, unsigned int *info_) {
    if (signatureMaxlen < sizeof(signature_t) || pathLen == 0 ) {
        return zxerr_invalid_crypto_settings;
    }

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32] = {0};
    volatile int signatureLength = 0;
    *info_ = 0;

    signature_t *const signature = (signature_t *) buffer;

    volatile zxerr_t error = zxerr_unknown;
    BEGIN_TRY
    {
        TRY
        {
            // Generate keys
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       pathLen,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);

            // Sign
            signatureLength = cx_ecdsa_sign(&cx_privateKey,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            message,
                                            messageLen,
                                            signature->der_signature,
                                            sizeof_field(signature_t, der_signature),
                                            info_);
            error = zxerr_ok;
        }
        CATCH_OTHER(e) {
            error = zxerr_ledger_api_error;
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    if (error != zxerr_ok) {
        return error;
    }

    err_convert_e err = convertDERtoRSV(signature->der_signature, *info_,  signature->r, signature->s, &signature->v);
    if (err != no_error) {
        // Error while converting so return length 0
        return zxerr_invalid_crypto_settings;
    }

    // return actual size using value from signatureLength
    *sigSize =  sizeof_field(signature_t, r) + sizeof_field(signature_t, s) + sizeof_field(signature_t, v) + signatureLength;
    return zxerr_ok;
}

// Sign a filecoin related transaction
zxerr_t crypto_sign(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize) {
    if (buffer == NULL || message == NULL || sigSize == NULL || signatureMaxlen < sizeof(signature_t)) {
        return zxerr_invalid_crypto_settings;
    }

    uint8_t tmp[BLAKE2B_256_SIZE] = {0};
    uint8_t message_digest[BLAKE2B_256_SIZE] = {0};

    blake_hash(message, messageLen, tmp, BLAKE2B_256_SIZE);
    blake_hash_cid(tmp, BLAKE2B_256_SIZE, message_digest, BLAKE2B_256_SIZE);

    info = 0;

    zxerr_t ret = _sign(buffer, signatureMaxlen, message_digest, BLAKE2B_256_SIZE, sigSize, hdPath, HDPATH_LEN_DEFAULT, &info);
    return ret;
}

zxerr_t crypto_sign_raw_bytes(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *digest, uint16_t messageLen, uint16_t *sigSize) {
    if (buffer == NULL || digest == NULL || sigSize == NULL || signatureMaxlen < sizeof(signature_t)) {
        return zxerr_invalid_crypto_settings;
    }
    info = 0;

    if (messageLen != BLAKE2B_256_SIZE)
        return zxerr_invalid_crypto_settings;

    zxerr_t ret = _sign(buffer, signatureMaxlen, digest, BLAKE2B_256_SIZE, sigSize, hdPath, HDPATH_LEN_DEFAULT, &info);
    return ret;
}

// Sign an ethereum related transaction
zxerr_t crypto_sign_eth(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize) {
    if (buffer == NULL || message == NULL || sigSize == NULL || signatureMaxlen < sizeof(signature_t)) {
        return zxerr_invalid_crypto_settings;
    }

    uint8_t message_digest[KECCAK_256_SIZE] = {0};
    keccak_digest(message, messageLen, message_digest, KECCAK_256_SIZE);

    zxerr_t error = _sign(buffer, signatureMaxlen, message_digest, KECCAK_256_SIZE, sigSize, hdPath, hdPath_len, &info);
    if (error != zxerr_ok){
        return zxerr_invalid_crypto_settings;
    }

    // we need to fix V
    uint8_t v = 0;
    zxerr_t err = tx_compute_eth_v(info, &v);

    if (err != zxerr_ok)
        return zxerr_invalid_crypto_settings;

    // need to reorder signature as hw-eth-app expects v at the beginning.
    // so rsv -> vrs
    uint8_t rs_size = sizeof_field(signature_t, r) + sizeof_field(signature_t, s);
    memmove(buffer + 1, buffer, rs_size);
    buffer[0] = v;

    return zxerr_ok;
}

typedef struct {
    uint8_t publicKey[SECP256K1_PK_LEN];

    // payload as described in https://filecoin-projectegithub.io/specs/#protocol-1-libsecpk1-elliptic-curve-public-keys
    // payload [prot][hashed(pk)]       // 1 + 20
    uint8_t addrBytesLen;
    uint8_t addrBytes[21];

    uint8_t addrStrLen;
    uint8_t addrStr[41];  // 41 = because (20+1+4)*8/5 (32 base encoded size)

} __attribute__((packed)) answer_t;

typedef struct {
    // plus 1-bytes to write pubkey len
    uint8_t publicKey[SECP256K1_PK_LEN + 1];
    // hex of the ethereum address plus 1-bytes
    // to write the address len
    uint8_t address[(ETH_ADDR_LEN * 2) + 1];  // 41 = because (20+1+4)*8/5 (32 base encoded size)
    // place holder for further dev
    uint8_t chainCode[32];

} __attribute__((packed)) answer_eth_t;

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    if (buffer == NULL || buffer_len < sizeof(answer_t) || addrLen == NULL) {
        return zxerr_no_data;
    }
    MEMZERO(buffer, buffer_len);
    answer_t *const answer = (answer_t *) buffer;

    CHECK_ZXERR(crypto_extractPublicKey(hdPath, answer->publicKey, sizeof_field(answer_t, publicKey), NULL))

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
    answer_eth_t *const answer = (answer_eth_t *) buffer;

    CHECK_ZXERR(crypto_extractPublicKey(hdPath, &answer->publicKey[1], sizeof_field(answer_eth_t, publicKey) - 1, &chain_code))

    answer->publicKey[0] = SECP256K1_PK_LEN;

    uint8_t hash[KECCAK_256_SIZE] = {0};

    keccak_digest(&answer->publicKey[2], SECP256K1_PK_LEN - 1, hash, KECCAK_256_SIZE);

    answer->address[0] = ETH_ADDR_LEN * 2;

    // get hex of the eth address(last 20 bytes of pubkey hash)
    char str[41] = {0};

    // take the last 20-bytes of the hash, they are the ethereum address
    array_to_hexstr(str, 41, hash + 12 , ETH_ADDR_LEN);
    MEMCPY(answer->address+1, str, 40);

    *addrLen = sizeof_field(answer_eth_t, publicKey) + sizeof_field(answer_eth_t, address);

    return zxerr_ok;
}

/*******************************************************************************
*   (c) 2019 Zondax GmbH
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
#include "coin.h"
#include "zxmacros.h"
#include "base32.h"
#include "zxformat.h"

uint32_t hdPath[HDPATH_LEN_DEFAULT];

bool isTestnet() {
    return hdPath[0] == HDPATH_0_TESTNET &&
           hdPath[1] == HDPATH_1_TESTNET;
}

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
#include "cx.h"

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];

    if (pubKeyLen < SECP256K1_PK_LEN) {
        return zxerr_invalid_crypto_settings;
    }

    zxerr_t error = zxerr_ok;
    BEGIN_TRY
    {
        TRY {
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);
            cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey);
            cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1);
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

__Z_INLINE int blake_hash(const unsigned char *in, unsigned int inLen,
               unsigned char *out, unsigned int outLen) {

    cx_blake2b_t ctx;
    cx_blake2b_init(&ctx, outLen * 8);
    cx_hash(&ctx.header, CX_LAST, in, inLen, out, outLen);

    return 0;
}

__Z_INLINE int blake_hash_cid(const unsigned char *in, unsigned int inLen,
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


zxerr_t crypto_sign(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize) {
    if (signatureMaxlen < sizeof(signature_t) ) {
        return zxerr_invalid_crypto_settings;
    }

    uint8_t tmp[BLAKE2B_256_SIZE];
    uint8_t message_digest[BLAKE2B_256_SIZE];

    blake_hash(message, messageLen, tmp, BLAKE2B_256_SIZE);
    blake_hash_cid(tmp, BLAKE2B_256_SIZE, message_digest, BLAKE2B_256_SIZE);

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];
    int signatureLength = 0;
    unsigned int info = 0;

    signature_t *const signature = (signature_t *) buffer;

    zxerr_t error = zxerr_ok;
    BEGIN_TRY
    {
        TRY
        {
            // Generate keys
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       hdPath,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);

            // Sign
            signatureLength = cx_ecdsa_sign(&cx_privateKey,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            message_digest,
                                            BLAKE2B_256_SIZE,
                                            signature->der_signature,
                                            sizeof_field(signature_t, der_signature),
                                            &info);
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

    err_convert_e err = convertDERtoRSV(signature->der_signature, info,  signature->r, signature->s, &signature->v);
    if (err != no_error) {
        // Error while converting so return length 0
        return zxerr_invalid_crypto_settings;
    }

    // return actual size using value from signatureLength
    *sigSize =  sizeof_field(signature_t, r) + sizeof_field(signature_t, s) + sizeof_field(signature_t, v) + signatureLength;
    return zxerr_ok;
}

#else

#include <hexutils.h>
#include "blake2.h"

char *crypto_testPubKey;

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    ///////////////////////////////////////
    // THIS IS ONLY USED FOR TEST PURPOSES
    ///////////////////////////////////////

    // Empty version for non-Ledger devices
    MEMZERO(pubKey, pubKeyLen);

    if (crypto_testPubKey != NULL) {
        parseHexString(pubKey, pubKeyLen, crypto_testPubKey);
    } else {
        const char *str = "0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991c140f664d2978ac0972a";
        parseHexString(pubKey, pubKeyLen, str);
    }

    return zxerr_ok;
}

__Z_INLINE int blake_hash(const unsigned char *in, unsigned int inLen,
                          unsigned char *out, unsigned int outLen) {
    blake2b_state s;
    blake2b_init(&s, outLen);
    blake2b_update(&s, in, inLen);
    blake2b_final(&s, out, outLen);
    return 0;
}

__Z_INLINE int blake_hash_cid(const unsigned char *in, unsigned int inLen,
                              unsigned char *out, unsigned int outLen) {

    uint8_t prefix[] = PREFIX;

    blake2b_state s;
    blake2b_init(&s, outLen);
    blake2b_update(&s, prefix, sizeof(prefix));
    blake2b_update(&s, in, inLen);
    blake2b_final(&s, out, outLen);

    return 0;
}

int prepareDigestToSign(const unsigned char *in, unsigned int inLen,
                        unsigned char *out, unsigned int outLen) {

    uint8_t tmp[BLAKE2B_256_SIZE];

    blake_hash(in, inLen, tmp, BLAKE2B_256_SIZE);
    blake_hash_cid(tmp, BLAKE2B_256_SIZE, out, outLen);

    return 0;
}

zxerr_t crypto_sign(uint8_t *signature, uint16_t signatureMaxlen,
                    const uint8_t *message, uint16_t messageLen,
                    uint16_t *sigSize) {
    // Empty version for non-Ledger devices
    uint8_t tmp[BLAKE2B_256_SIZE];
    uint8_t message_digest[BLAKE2B_256_SIZE];

    blake_hash(message, messageLen, tmp, BLAKE2B_256_SIZE);
    blake_hash_cid(tmp, BLAKE2B_256_SIZE, message_digest, BLAKE2B_256_SIZE);

    return zxerr_ok;
}

#endif

uint8_t decompressLEB128(const uint8_t *input, uint16_t inputSize, uint64_t *v) {
    unsigned int i = 0;

    *v = 0;
    uint16_t shift = 0;
    while (i < 10u && i < inputSize) {
        uint64_t b = input[i] & 0x7fu;

        if (shift >= 63 && b > 1) {
            // This will overflow uint64_t
            break;
        }

        *v |= b << shift;

        if (!(input[i] & 0x80u)) {
            return 1;
        }

        shift += 7;
        i++;
    }

    // exit because of overflowing outputSize
    *v = 0;
    return 0;
}

uint16_t formatProtocol(const uint8_t *addressBytes,
                        uint16_t addressSize,
                        uint8_t *formattedAddress,
                        uint16_t formattedAddressSize) {
    if (formattedAddress == NULL || formattedAddressSize < 2u) {
        return 0;
    }
    if (addressBytes == NULL || addressSize < 2u) {
        return 0;
    }

    const uint8_t protocol = addressBytes[0];

    formattedAddress[0] = isTestnet() ? 't' : 'f';
    formattedAddress[1] = (char) (protocol + '0');

    uint16_t payloadSize = 0;
    switch (protocol) {
        case ADDRESS_PROTOCOL_ID: {
            uint64_t val = 0;

            if (!decompressLEB128(addressBytes + 1, addressSize - 1, &val)) {
                return 0;
            }

            if (uint64_to_str((char *) formattedAddress + 2,
                              (uint32_t) (formattedAddressSize - 2),
                              val) != NULL) {
                return 0;
            }

            return strlen((const char *) formattedAddress);
        }
        case ADDRESS_PROTOCOL_SECP256K1: {  // NOLINT(bugprone-branch-clone)
            // payload 20 bytes + 4 bytes checksum
            payloadSize = ADDRESS_PROTOCOL_SECP256K1_PAYLOAD_LEN;
            break;
        }
        case ADDRESS_PROTOCOL_ACTOR: {  // NOLINT(bugprone-branch-clone)
            // payload 20 bytes + 4 bytes checksum
            payloadSize = ADDRESS_PROTOCOL_ACTOR_PAYLOAD_LEN;
            break;
        }
        case ADDRESS_PROTOCOL_BLS: {
            // payload 20 bytes + 4 bytes checksum
            payloadSize = ADDRESS_PROTOCOL_BLS_PAYLOAD_LEN;
            break;
        }
        default:
            return 0;
    }

    // Remove first byte which is the protocol byte
    if (addressSize != payloadSize + 1) {
        return 0;
    }

    uint8_t payload_crc[ADDRESS_PROTOCOL_BLS_PAYLOAD_LEN + CHECKSUM_LENGTH]; // Max size 52 bytes

    //We don't want the first byte which is the protocol byte
    MEMCPY(payload_crc, addressBytes + 1, addressSize - 1);
    // append 4 bytes checksum to payload_crc
    blake_hash(addressBytes, addressSize, payload_crc + payloadSize, CHECKSUM_LENGTH);

    // Now prepare the address output
    if (base32_encode(payload_crc,
                      (uint32_t) (payloadSize + CHECKSUM_LENGTH),
                      (char *)(formattedAddress + 2),
                      (uint32_t) (formattedAddressSize - 2)) < 0) {
        return 0;
    }

    return strnlen((char *) formattedAddress, formattedAddressSize);
}

typedef struct {
    uint8_t publicKey[SECP256K1_PK_LEN];

    // payload as described in https://filecoin-project.github.io/specs/#protocol-1-libsecpk1-elliptic-curve-public-keys
    // payload [prot][hashed(pk)]       // 1 + 20
    uint8_t addrBytesLen;
    uint8_t addrBytes[21];

    uint8_t addrStrLen;
    uint8_t addrStr[41];  // 41 = because (20+1+4)*8/5 (32 base encoded size)

} __attribute__((packed)) answer_t;

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    if (buffer_len < sizeof(answer_t)) {
        return 0;
    }
    MEMZERO(buffer, buffer_len);
    answer_t *const answer = (answer_t *) buffer;

    CHECK_ZXERR(crypto_extractPublicKey(hdPath, answer->publicKey, sizeof_field(answer_t, publicKey)))

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

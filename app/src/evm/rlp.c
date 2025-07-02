/*******************************************************************************
 *   (c) 2018 - 2023 ZondaX AG
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
#include "rlp.h"

#include "zxformat.h"
#include "zxmacros.h"

parser_error_t rlp_parseStream(parser_context_t *ctx, rlp_t *rlp, uint16_t *fields, uint16_t maxFields) {
    if (ctx == NULL || rlp == NULL || fields == NULL) {
        return parser_unexpected_error;
    }
    *fields = 0;
    while (ctx->offset < ctx->bufferLen && (*fields) < maxFields) {
        CHECK_PARSER_ERR(rlp_read(ctx, rlp))
        (*fields)++;
        rlp++;
    }

    return parser_ok;
}

static parser_error_t readBytes(parser_context_t *ctx, uint8_t const **buff, uint64_t buffLen) {
    if (ctx->bufferLen - ctx->offset < buffLen) {
        return parser_unexpected_buffer_end;
    }
    *buff = ctx->buffer + ctx->offset;
    ctx->offset += buffLen;
    return parser_ok;
}

parser_error_t rlp_read(parser_context_t *ctx, rlp_t *rlp) {
    if (ctx == NULL || rlp == NULL) {
        return parser_unexpected_error;
    }

    const uint8_t *prefixPtr = NULL;
    CHECK_PARSER_ERR(readBytes(ctx, &prefixPtr, 1))
    const uint8_t prefix = *prefixPtr;

    if (prefix <= RLP_KIND_BYTE_PREFIX) {
        rlp->kind = RLP_KIND_BYTE;
        rlp->ptr = prefixPtr;
        rlp->rlpLen = 0;

    } else if (prefix <= RLP_KIND_STRING_SHORT_MAX) {
        rlp->kind = RLP_KIND_STRING;
        rlp->rlpLen = prefix - RLP_KIND_STRING_SHORT_MIN;
        if (rlp->rlpLen == 0) {
            rlp->ptr = prefixPtr;
        } else {
            CHECK_PARSER_ERR(readBytes(ctx, &rlp->ptr, rlp->rlpLen))
        }

    } else if (prefix <= RLP_KIND_STRING_LONG_MAX) {
        rlp->kind = RLP_KIND_STRING;
        const uint8_t bytesLen = prefix - RLP_KIND_STRING_SHORT_MAX;
        const uint8_t *rlpLenPtr = NULL;
        CHECK_PARSER_ERR(readBytes(ctx, &rlpLenPtr, bytesLen))
        rlp->rlpLen = 0;
        for (uint8_t i = 0; i < bytesLen; i++) {
            rlp->rlpLen <<= 8u;
            rlp->rlpLen += *(rlpLenPtr + i);
        }
        CHECK_PARSER_ERR(readBytes(ctx, &rlp->ptr, rlp->rlpLen))

    } else if (prefix <= RLP_KIND_LIST_SHORT_MAX) {
        rlp->kind = RLP_KIND_LIST;
        rlp->rlpLen = prefix - RLP_KIND_LIST_SHORT_MIN;
        CHECK_PARSER_ERR(readBytes(ctx, &rlp->ptr, rlp->rlpLen))

    } else {
        rlp->kind = RLP_KIND_LIST;
        const uint8_t bytesLen = prefix - RLP_KIND_LIST_SHORT_MAX;
        const uint8_t *rlpLenPtr = NULL;
        CHECK_PARSER_ERR(readBytes(ctx, &rlpLenPtr, bytesLen))
        rlp->rlpLen = 0;
        for (uint8_t i = 0; i < bytesLen; i++) {
            rlp->rlpLen <<= 8u;
            rlp->rlpLen += *(rlpLenPtr + i);
        }
        CHECK_PARSER_ERR(readBytes(ctx, &rlp->ptr, rlp->rlpLen))
    }

    return parser_ok;
}

parser_error_t rlp_readList(const rlp_t *list, rlp_t *fields, uint16_t *listFields, uint16_t maxFields) {
    if (list == NULL || list->kind != RLP_KIND_LIST || fields == NULL || listFields == NULL) {
        return parser_unexpected_error;
    }

    parser_context_t ctx = {.buffer = list->ptr, .bufferLen = list->rlpLen, .offset = 0, .tx_type = eth_tx};
    return rlp_parseStream(&ctx, fields, listFields, maxFields);
}

parser_error_t rlp_readUInt256(const rlp_t *rlp, uint256_t *value) {
    if (rlp == NULL || value == NULL) {
        return parser_unexpected_error;
    }

    uint8_t tmpBuffer[32] = {0};
    switch (rlp->kind) {
        case RLP_KIND_STRING:
            if (rlp->rlpLen > sizeof(tmpBuffer)) return parser_value_out_of_range;
            MEMCPY(tmpBuffer + (sizeof(tmpBuffer) - rlp->rlpLen), rlp->ptr, rlp->rlpLen);
            break;

        case RLP_KIND_BYTE:
            tmpBuffer[31] = *rlp->ptr;
            break;

        default:
            return parser_unexpected_type;
    }

    parser_context_t ctx = {.buffer = tmpBuffer, .bufferLen = sizeof(tmpBuffer), .offset = 0, .tx_type = eth_tx};
    CHECK_PARSER_ERR(readu256BE(&ctx, value));
    return parser_ok;
}

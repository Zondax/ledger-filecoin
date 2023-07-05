/*******************************************************************************
 *  (c) 2018 - 2023 Zondax AG
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

#include "parser_data_cap.h"
#include "app_mode.h"
#include "cbor.h"
#include "coin.h"
#include "common/parser_common.h"
#include "crypto.h"
#include "fil_utils.h"
#include "parser_txdef.h"
#include "zxformat.h"
#include <stdio.h>
#include <string.h>
#include <zxmacros.h>

#define MB_DECIMAL_PLACES 6
#define DATA_CAP_PREFIX_LEN 18

static const char dataCapPrefix[] = "fil_removedatacap:";

__Z_INLINE parser_error_t parse_proposal_id(uint64_t *proposal_id,
                                            CborValue *value) {
  CborValue internal = *value;
  CborValue container;

  CborType tpy = cbor_value_get_type(value);
  switch (tpy) {
  case CborIntegerType: {
    PARSER_ASSERT_OR_ERROR(cbor_value_is_integer(value), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(
        cbor_value_get_int64_checked(value, (int64_t *)proposal_id))
    return parser_ok;
  }

  case CborArrayType: {
    size_t arraySize;
    CHECK_CBOR_MAP_ERR(cbor_value_get_array_length(&internal, &arraySize))
    PARSER_ASSERT_OR_ERROR(arraySize == 1, parser_unexpected_number_items)
    zemu_log_stack("array_1_element");

    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&internal),
                           parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&internal, &container))
    PARSER_ASSERT_OR_ERROR(cbor_value_is_integer(&container),
                           parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(
        cbor_value_get_int64_checked(&container, (int64_t *)proposal_id))
    return parser_ok;
  }

  default:
    return parser_unexpected_type;
  }
}

__Z_INLINE parser_error_t parse_address(address_t *addr, CborValue *value) {

  CHECK_PARSER_ERR(readAddress(addr, value))

  // SignRemoveDataCap proposal require addresses to be of type ID
  // https://github.com/filecoin-project/go-state-types/blob/master/builtin/v9/verifreg/verifreg_types.go#L16
  if (addr->buffer[0] != ADDRESS_PROTOCOL_ID)
    return parser_invalid_address;

  return parser_ok;
}

parser_error_t _readDataCap(parser_context_t *ctx, remove_datacap_t *tx) {

  const uint8_t *prefix = ctx->buffer + ctx->offset;

  // The prefix is not cbor-encoded, but plain text.
  if (strncmp((char *)prefix, dataCapPrefix, DATA_CAP_PREFIX_LEN) != 0)
    return parser_invalid_datacap_prefix;

  // skip the header
  ctx->offset += DATA_CAP_PREFIX_LEN;

  // continue parsing proposal data which is encoded using CBOR
  CborValue it;
  INIT_CBOR_PARSER(ctx, it)
  PARSER_ASSERT_OR_ERROR(!cbor_value_at_end(&it), parser_unexpected_buffer_end)

  // It is an array
  PARSER_ASSERT_OR_ERROR(cbor_value_is_array(&it), parser_unexpected_type)
  size_t arraySize;
  CHECK_CBOR_MAP_ERR(cbor_value_get_array_length(&it, &arraySize))

  PARSER_ASSERT_OR_ERROR(arraySize == 3, parser_unexpected_number_items)

  CborValue arrayContainer;
  PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&it), parser_unexpected_type)
  CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&it, &arrayContainer))

  // "client" field
  CHECK_PARSER_ERR(parse_address(&tx->client, &arrayContainer))
  PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType,
                         parser_unexpected_type)
  CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

  // "amount" field
  CHECK_PARSER_ERR(readBigInt(&tx->amount, &arrayContainer))
  PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType,
                         parser_unexpected_type)
  CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

  // proposal_id
  CHECK_PARSER_ERR(parse_proposal_id(&tx->proposal_id, &arrayContainer))
  PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType,
                         parser_unexpected_type)
  CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

  CHECK_CBOR_MAP_ERR(cbor_value_leave_container(&it, &arrayContainer))

  // End of buffer does not match end of parsed data
  PARSER_ASSERT_OR_ERROR(it.ptr == ctx->buffer + ctx->bufferLen,
                         parser_cbor_unexpected_EOF)

  return parser_ok;
}

parser_error_t _validateDataCap(__Z_UNUSED const parser_context_t *c) {
  // Note: This is place holder for transaction level checks that the project
  // may require before accepting the parsed values. the parser already
  // validates input This function is called by parser_validate, where
  // additional checks are made (formatting, UI/UX, etc.(
  return parser_ok;
}

uint8_t _getNumItemsDataCap(__Z_UNUSED const parser_context_t *c) {
  // client
  // allowance to be removed
  // proposal_id
  return 3;
}

parser_error_t _getItemDataCap(__Z_UNUSED const parser_context_t *ctx,
                               uint8_t displayIdx, char *outKey,
                               uint16_t outKeyLen, char *outVal,
                               uint16_t outValLen, uint8_t pageIdx,
                               uint8_t *pageCount) {

  MEMZERO(outKey, outKeyLen);
  MEMZERO(outVal, outValLen);
  snprintf(outKey, outKeyLen, "?");
  snprintf(outVal, outValLen, " ");

  CHECK_APP_CANARY()

  if (displayIdx == 0) {
    snprintf(outKey, outKeyLen, "ProposalID");
    if (int64_to_str(outVal, outValLen,
                     (int64_t)parser_tx_obj.rem_datacap_tx.proposal_id) !=
        NULL) {
      return parser_unexepected_error;
    }
    *pageCount = 1;
    return parser_ok;
  }

  if (displayIdx == 1) {
    snprintf(outKey, outKeyLen, "Client ");
    return printAddress(&parser_tx_obj.rem_datacap_tx.client, outVal, outValLen,
                        pageIdx, pageCount);
  }

  if (displayIdx == 2) {
    snprintf(outKey, outKeyLen, "allowanceToRem(MB) ");
    return parser_printBigIntFixedPoint(&parser_tx_obj.rem_datacap_tx.amount,
                                        outVal, outValLen, pageIdx, pageCount,
                                        MB_DECIMAL_PLACES);
  }

  return parser_no_data;
}

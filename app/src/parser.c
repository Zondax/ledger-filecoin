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

#include "parser.h"
#include "app_mode.h"
#include "bignum.h"
#include "coin.h"
#include "common/parser_common.h"
#include "fil_utils.h"
#include "parser_client_deal.h"
#include "parser_impl.h"
#include "parser_impl_eth.h"
#include "parser_raw_bytes.h"
#include "parser_txdef.h"
#include "zxformat.h"
#include <stdio.h>
#include <zxmacros.h>
#include "parser_invoke_evm.h"

#define TRANSFER_METHOD 0

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX) || defined(TARGET_FLEX)
// For some reason NanoX requires this function
void __assert_fail(__Z_UNUSED const char *assertion,
                   __Z_UNUSED const char *file, __Z_UNUSED unsigned int line,
                   __Z_UNUSED const char *function) {
  while (1) {
  };
}
#endif

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer,
                           uint16_t bufferSize);

static parser_error_t parser_init_context(parser_context_t *ctx,
                                          const uint8_t *buffer,
                                          uint16_t bufferSize) {
  ctx->offset = 0;
  ctx->buffer = NULL;
  ctx->bufferLen = 0;

  if (bufferSize == 0 || buffer == NULL) {
    // Not available, use defaults
    return parser_init_context_empty;
  }

  ctx->buffer = buffer;
  ctx->bufferLen = bufferSize;

  memset(&parser_tx_obj, 0, sizeof(parser_tx_obj));

  return parser_ok;
}

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer,
                           uint16_t bufferSize) {
  CHECK_PARSER_ERR(parser_init_context(ctx, buffer, bufferSize))
  return parser_ok;
}

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data,
                            size_t dataLen) {
  zemu_log_stack("parser_parse");

  switch (ctx->tx_type) {
  case fil_tx: {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    app_mode_skip_blindsign_ui(); 
    return _read(ctx, &(parser_tx_obj.base_tx));
  }
  case eth_tx: {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    return _readEth(ctx, &eth_tx_obj);
  }
  case clientdeal_tx: {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    app_mode_skip_blindsign_ui(); 
    return _readClientDeal(ctx, &parser_tx_obj.client_deal_tx);
  }
  case raw_bytes: {
    // Processing raw-bytes is valid only in expert mode
    if (!app_mode_blindsign())
      return parser_blindsign_required;

    return _readRawBytes(ctx, &parser_tx_obj.raw_bytes_tx);
  }
  default:
    return parser_unsupported_tx;
  }
}

parser_error_t parser_validate(const parser_context_t *ctx) {
  zemu_log_stack("parser_validate\n");

  // Call especific fil transaction implementation for data validation
  switch (ctx->tx_type) {
  case fil_tx: {
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj.base_tx))
    break;
  }
  case eth_tx: {
    CHECK_PARSER_ERR(_validateTxEth())
    break;
  }
  case clientdeal_tx: {
    CHECK_PARSER_ERR(_validateClientDeal(ctx))
    break;
  }
  case raw_bytes: {
    CHECK_PARSER_ERR(_validateRawBytes(ctx))
    break;
  }
  default:
    return parser_unsupported_tx;
  }

  // Iterate through all items to check that all can be shown and are valid
  uint8_t numItems = 0;
  CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems));

  char tmpKey[40] = {0};
  char tmpVal[40] = {0};

  for (uint8_t idx = 0; idx < numItems; idx++) {
    uint8_t pageCount = 0;
    CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal,
                                    sizeof(tmpVal), 0, &pageCount))
  }

  return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx,
                                  uint8_t *num_items) {
  switch (ctx->tx_type) {
  case fil_tx: {
    *num_items = _getNumItems(ctx, &parser_tx_obj.base_tx);
    break;
  }
  case eth_tx: {
    CHECK_PARSER_ERR(_getNumItemsEth(num_items));
    break;
  }
  case clientdeal_tx: {
    *num_items = _getNumItemsClientDeal(ctx);
    break;
  }
  case raw_bytes: {
    *num_items = _getNumItemsRawBytes(ctx);
    break;
  }
  default:
    return parser_unsupported_tx;
  }
  return parser_ok;
}

parser_error_t parser_printParam(const fil_base_tx_t *tx, uint8_t paramIdx,
                                 char *outVal, uint16_t outValLen,
                                 uint8_t pageIdx, uint8_t *pageCount) {
  return _printParam(tx, paramIdx, outVal, outValLen, pageIdx, pageCount);
}

static parser_error_t printMethod(char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {
  snprintf(outKey, outKeyLen, "Method ");
  *pageCount = 1;

  switch (parser_tx_obj.base_tx.method) {
    case TRANSFER_METHOD:
      snprintf(outVal, outValLen, "Transfer ");
      break;
    case INVOKE_EVM_METHOD:
      snprintf(outVal, outValLen, "Invoke EVM ");
      break;

    default: {
      char buffer[100];
      MEMZERO(buffer, sizeof(buffer));
      fpuint64_to_str(buffer, sizeof(buffer), parser_tx_obj.base_tx.method, 0);
      pageString(outVal, outValLen, buffer, pageIdx, pageCount);
      break;
    }
  }

  return parser_ok;
}

parser_error_t _getItemFil(const parser_context_t *ctx, uint8_t displayIdx,
                           char *outKey, uint16_t outKeyLen, char *outVal,
                           uint16_t outValLen, uint8_t pageIdx,
                           uint8_t *pageCount) {

    const bool expert_mode = app_mode_expert();

    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
    *pageCount = 0;

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    if (displayIdx >= numItems) {
        return parser_no_data;
    }

    // If the transaction is InvokeEVM and it's a transfer from ERC20 token
    if (isInvokeEVM_ERC20Transfer(&parser_tx_obj.base_tx)) {
        return printInvokeEVM(&parser_tx_obj.base_tx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    // For InvokeEVM methods, expert mode is required
    if (parser_tx_obj.base_tx.method == INVOKE_EVM_METHOD && !app_mode_expert()) {
      return parser_expert_mode_required;
    }

    uint8_t adjustedIndex = displayIdx;
    if (parser_tx_obj.base_tx.to.buffer[0] != ADDRESS_PROTOCOL_DELEGATED) {
        adjustedIndex++;
    }

    if (adjustedIndex >= 2 && parser_tx_obj.base_tx.from.buffer[0] != ADDRESS_PROTOCOL_DELEGATED) {
        adjustedIndex++;
    }

    // Normal mode: 6 fields [To | From | Value | Gas Limit | Gas Fee Cap |
    // Method] + Params (variable length) Expert mode: 8 fields [To | From | Value
    // | Gas Limit | Gas Fee Cap | Gas Premium | Nonce | Method] + Params
    // (variable length)
    switch (adjustedIndex) {
        case 0:
            snprintf(outKey, outKeyLen, "To ");
            return printEthAddress(&parser_tx_obj.base_tx.to, outVal, outValLen, pageIdx,
                                pageCount);
        case 1:
            snprintf(outKey, outKeyLen, "To ");
            return printAddress(&parser_tx_obj.base_tx.to, outVal, outValLen, pageIdx,
                                pageCount);
        case 2:
            snprintf(outKey, outKeyLen, "From ");
            return printEthAddress(&parser_tx_obj.base_tx.from, outVal, outValLen, pageIdx,
                                pageCount);
        case 3:
            snprintf(outKey, outKeyLen, "From ");
            return printAddress(&parser_tx_obj.base_tx.from, outVal, outValLen, pageIdx,
                                pageCount);
        case 4:
            snprintf(outKey, outKeyLen, "Value ");
            return parser_printBigIntFixedPoint(&parser_tx_obj.base_tx.value, outVal,
                                                outValLen, pageIdx, pageCount,
                                                COIN_AMOUNT_DECIMAL_PLACES);

        case 5: {
            char tmpBuffer[80] = {0};
            snprintf(outKey, outKeyLen, "Gas Limit ");
            if (int64_to_str(tmpBuffer, sizeof(tmpBuffer), parser_tx_obj.base_tx.gaslimit) != NULL) {
                return parser_unexpected_error;
            }

            if (insertDecimalPoint(tmpBuffer, sizeof(tmpBuffer), COIN_AMOUNT_DECIMAL_PLACES) != zxerr_ok) {
                return parser_unexpected_error;
            }
            if (z_str3join(tmpBuffer, sizeof(tmpBuffer), "FIL ", NULL) != zxerr_ok) {
                return parser_unexpected_error;
            }

            pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
            return parser_ok;
        }

        case 6:
            snprintf(outKey, outKeyLen, "Gas Fee Cap ");
            return parser_printBigIntFixedPoint(&parser_tx_obj.base_tx.gasfeecap,
                                                outVal, outValLen, pageIdx, pageCount,
                                                COIN_AMOUNT_DECIMAL_PLACES);

        case 7:
            if (expert_mode) {
            snprintf(outKey, outKeyLen, "Gas Premium ");
            return parser_printBigIntFixedPoint(&parser_tx_obj.base_tx.gaspremium,
                                                outVal, outValLen, pageIdx, pageCount,
                                                COIN_AMOUNT_DECIMAL_PLACES);
            }
            return printMethod(outKey, outKeyLen, outVal, outValLen, pageIdx,
                            pageCount);

        case 8:
            if (expert_mode) {
            snprintf(outKey, outKeyLen, "Nonce ");
            if (uint64_to_str(outVal, outValLen, parser_tx_obj.base_tx.nonce) !=
                NULL) {
                return parser_unexpected_error;
            }
            *pageCount = 1;
            return parser_ok;
            }
            // For non expert mode this index represent params field.
            break;

        case 9:
            if (expert_mode) {
            return printMethod(outKey, outKeyLen, outVal, outValLen, pageIdx,
                                pageCount);
            }
            // For non expert mode this index represent params field.
            break;

        default:
            break;
    }

    if (parser_tx_obj.base_tx.numparams == 0) {
        snprintf(outKey, outKeyLen, "Params ");
        snprintf(outVal, outValLen, "- NONE -");
        return parser_ok;
    }

    // remaining display pages show the params
    int32_t paramIdxSigned =
        displayIdx - (numItems - parser_tx_obj.base_tx.numparams);

    // end of params
    if (paramIdxSigned < 0 || paramIdxSigned >= parser_tx_obj.base_tx.numparams) {
        return parser_unexpected_field;
    }

    uint8_t paramIdx = (uint8_t)paramIdxSigned;
    *pageCount = 1;
    snprintf(outKey, outKeyLen, "Params |%d| ", paramIdx + 1);

    zemu_log_stack(outKey);
    return parser_printParam(&parser_tx_obj.base_tx, paramIdx, outVal, outValLen,
                            pageIdx, pageCount);
}

parser_error_t parser_getItem(const parser_context_t *ctx, uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen, char *outVal,
                              uint16_t outValLen, uint8_t pageIdx,
                              uint8_t *pageCount) {

  switch (ctx->tx_type) {
  case fil_tx: {
    return _getItemFil(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen,
                       pageIdx, pageCount);
  }
  case eth_tx: {
    return _getItemEth(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen,
                       pageIdx, pageCount);
  }
  case clientdeal_tx: {
    return _getItemClientDeal(ctx, displayIdx, outKey, outKeyLen, outVal,
                              outValLen, pageIdx, pageCount);
  }
  case raw_bytes: {
    // for now just display the hash
    return _getItemRawBytes(ctx, displayIdx, outKey, outKeyLen, outVal,
                            outValLen, pageIdx, pageCount);
  }
  default:
    return parser_unsupported_tx;
  }
}

parser_error_t parser_compute_eth_v(parser_context_t *ctx, unsigned int info,
                                    uint8_t *v) {
  return _computeV(ctx, &eth_tx_obj, info, v);
}

parser_error_t parser_rawbytes_init(uint8_t *buf, size_t buf_len) {

  return raw_bytes_init(buf, buf_len);
}
parser_error_t parser_rawbytes_update(uint8_t *buf, size_t buf_len) {
  return raw_bytes_update(buf, buf_len);
}
uint8_t *parser_rawbytes_hash() { return parser_tx_obj.raw_bytes_tx.digest; }
size_t parser_rawbytes_hash_len() {
  return sizeof(parser_tx_obj.raw_bytes_tx.digest);
}

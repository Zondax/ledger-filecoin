# Filecoin App

## General structure

The general structure of commands and responses is as follows:

#### Commands

| Field   | Type     | Content                | Note |
| :------ | :------- | :--------------------- | ---- |
| CLA     | byte (1) | Application Identifier | 0x06 |
| INS     | byte (1) | Instruction ID         |      |
| P1      | byte (1) | Parameter 1            |      |
| P2      | byte (1) | Parameter 2            |      |
| L       | byte (1) | Bytes in payload       |      |
| PAYLOAD | byte (L) | Payload                |      |

#### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ANSWER  | byte (?) | Answer      | depends on the command   |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

#### Return codes

| Return code | Description             |
| ----------- | ----------------------- |
| 0x6400      | Execution Error         |
| 0x6982      | Empty buffer            |
| 0x6983      | Output buffer too small |
| 0x6986      | Command not allowed     |
| 0x6D00      | INS not supported       |
| 0x6E00      | CLA not supported       |
| 0x6F00      | Unknown                 |
| 0x9000      | Success                 |

---------

## Command definition

### GET_VERSION

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | 0x06     |
| INS   | byte (1) | Instruction ID         | 0x00     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field   | Type     | Content          | Note                            |
| ------- | -------- | ---------------- | ------------------------------- |
| TEST    | byte (1) | Test Mode        | 0xFF means test mode is enabled |
| MAJOR   | byte (1) | Version Major    |                                 |
| MINOR   | byte (1) | Version Minor    |                                 |
| PATCH   | byte (1) | Version Patch    |                                 |
| LOCKED  | byte (1) | Device is locked |                                 |
| SW1-SW2 | byte (2) | Return code      | see list of return codes        |

--------------

### INS_GET_ADDR_SECP256K1

#### Command

| Field      | Type           | Content                   | Expected          |
| ---------- | -------------- | ------------------------- | ----------------- |
| CLA        | byte (1)       | Application Identifier    | 0x06              |
| INS        | byte (1)       | Instruction ID            | 0x01              |
| P1         | byte (1)       | Request User confirmation | No = 0 / Yes = 1  |
| P2         | byte (1)       | Parameter 2               | ignored           |
| L          | byte (1)       | Bytes in payload          | (depends)         |
| Path[0]    | byte (4)       | Derivation Path Data      | 0x8000002c (44')  |
| Path[1]    | byte (4)       | Derivation Path Data      | 0x800001cd (461') |
| Path[2]    | byte (4)       | Derivation Path Data      | ?                 |
| Path[3]    | byte (4)       | Derivation Path Data      | ?                 |
| Path[4]    | byte (4)       | Derivation Path Data      | ?                 |

#### Response

| Field      | Type      | Content           | Note                                                                                              |
| ---------- | --------- | ----------------- | ------------------------------------------------------------------------------------------------- |
| PK         | byte (65) | Public Key        |                                                                                                   |
| ADDR_B_LEN | byte (1)  | ADDR_B Length     |[Specs](https://filecoin-project.github.io/specs/#protocol-1-libsecpk1-elliptic-curve-public-keys) |
| ADDR_B     | byte (??) | Address as Bytes  |                                                                                                   |
| ADDR_S_LEN | byte (1)  | ADDR_S Len        |[Specs](https://filecoin-project.github.io/specs/#protocol-1-libsecpk1-elliptic-curve-public-keys) |
| ADDR_S     | byte (??) | Address as String |                                                                                                   |
| SW1-SW2    | byte (2)  | Return code       | see list of return codes                                                                          |

### INS_SIGN_SECP256K1

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | 0x06      |
| INS   | byte (1) | Instruction ID         | 0x02      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks contain data chunks that are described below

*First Packet*

| Field      | Type     | Content                | Expected          |
| ---------- | -------- | ---------------------- | ----------------- |
| Path[0]    | byte (4) | Derivation Path Data   | 0x8000002c (44')  |
| Path[1]    | byte (4) | Derivation Path Data   | 0x800001cd (461') |
| Path[2]    | byte (4) | Derivation Path Data   | ?                 |
| Path[3]    | byte (4) | Derivation Path Data   | ?                 |
| Path[4]    | byte (4) | Derivation Path Data   | ?                 |

*Other Chunks/Packets*

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Data    | bytes... | Message         |          |

Data is defined as:

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Message | bytes..  | CBOR data to sign   |      |

#### Response

| Field       | Type            | Content     | Note                     |
| ----------- | --------------- | ----------- | ------------------------ |
| secp256k1 R | byte (32)       | Signature   |                          |
| secp256k1 S | byte (32)       | Signature   |                          |
| secp256k1 V | byte (1)        | Signature   |                          |
| SIG         | byte (variable) | Signature   | DER format               |
| SW1-SW2     | byte (2)        | Return code | see list of return codes |

--------------

### INS_SIGN_RAW_BYTES

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | 0x06      |
| INS   | byte (1) | Instruction ID         | 0x07      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks contain raw data chunks

*First Packet*

| Field      | Type     | Content                | Expected          |
| ---------- | -------- | ---------------------- | ----------------- |
| Path[0]    | byte (4) | Derivation Path Data   | 0x8000002c (44')  |
| Path[1]    | byte (4) | Derivation Path Data   | 0x800001cd (461') |
| Path[2]    | byte (4) | Derivation Path Data   | ?                 |
| Path[3]    | byte (4) | Derivation Path Data   | ?                 |
| Path[4]    | byte (4) | Derivation Path Data   | ?                 |

*Other Chunks/Packets*

| Field     | Type     | Content             | Expected |
| --------- | -------- | ------------------- | -------- |
| Data size | byte (4) | Size of msg to sign | ?        |
| Data      | bytes... | Raw data            |          |

#### Response

| Field       | Type            | Content     | Note                     |
| ----------- | --------------- | ----------- | ------------------------ |
| secp256k1 R | byte (32)       | Signature   |                          |
| secp256k1 S | byte (32)       | Signature   |                          |
| secp256k1 V | byte (1)        | Signature   |                          |
| SIG         | byte (variable) | Signature   | DER format               |
| SW1-SW2     | byte (2)        | Return code | see list of return codes |

--------------

### INS_SIGN_PERSONAL_MESSAGE

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | 0x06      |
| INS   | byte (1) | Instruction ID         | 0x08      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks contain message data chunks

*First Packet*

| Field      | Type     | Content                | Expected          |
| ---------- | -------- | ---------------------- | ----------------- |
| Path[0]    | byte (4) | Derivation Path Data   | 0x8000002c (44')  |
| Path[1]    | byte (4) | Derivation Path Data   | 0x800001cd (461') |
| Path[2]    | byte (4) | Derivation Path Data   | ?                 |
| Path[3]    | byte (4) | Derivation Path Data   | ?                 |
| Path[4]    | byte (4) | Derivation Path Data   | ?                 |

*Other Chunks/Packets*

| Field     | Type     | Content             | Expected |
| --------- | -------- | ------------------- | -------- |
| Data size | byte (4) | Size of msg to sign | ?        |
| Data      | bytes... | Personal Message    |          |

#### Response

| Field       | Type      | Content     | Note                     |
| ----------- | --------- | ----------- | ------------------------ |
| secp256k1 V | byte (1)  | Signature   |                          |
| secp256k1 R | byte (32) | Signature   |                          |
| secp256k1 S | byte (32) | Signature   |                          |
| SW1-SW2     | byte (2)  | Return code | see list of return codes |

--------------

## ETH INSTRUCTIONS

For eth instructions the derivation path length can vary between 3 and 5 elements.

### INS_GET_ADDR_ETH

#### Command

| Field   | Type            | Content                   | Expected                                |
| ------- | --------------- | ------------------------- | --------------------------------------- |
| CLA     | byte (1)        | Application Identifier    | 0xE0                                    |
| INS     | byte (1)        | Instruction ID            | 0x02                                    |
| P1      | byte (1)        | Request User confirmation | No = 0 / Yes = 1                        |
| P2      | byte (1)        | Chain code                | no chain code - 0x0 / chain code - 0x01 |
| L       | byte (1)        | Bytes in payload          | (depends)                               |
| Path[0] | byte (4)        | Derivation Path Data      | 0x8000002c (44')                        |
| Path[1] | byte (4)        | Derivation Path Data      | 0x8000003c (60')                        |
| Path[2] | byte (4)        | Derivation Path Data      | ?                                       |
| Path[3] | byte (4)        | Derivation Path Data      | ?                                       |
| Path[4] | byte (4)        | Derivation Path Data      | ?                                       |

#### Response

| Field   | Type      | Content         | Note                               |
| ------- | --------- | --------------- | ---------------------------------- |
| PK LEN  | byte      | Public Key Len  |                                    |
| PK      | byte (??) | Public Key      |                                    |
| ADDR LEN| byte      | Address Len     |                                    |
| ADDR    | byte (??) | address         | Hex representation of eth address  |
| SW1-SW2 | byte (2)  | Return code     | see list of return codes           |

---

### INS_SIGN_ETH

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | 0xE0      |
| INS   | byte (1) | Instruction ID         | 0x04      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks contain data chunks that are described below

##### First Packet

| Field   | Type     | Content              | Expected         |
| ------- | -------- | -------------------- | ---------------- |
| Path[0] | byte (4) | Derivation Path Data | 0x8000002c (44') |
| Path[1] | byte (4) | Derivation Path Data | 0x8000003c (60') |
| Path[2] | byte (4) | Derivation Path Data | ?                |
| Path[3] | byte (4) | Derivation Path Data | ?                |
| Path[4] | byte (4) | Derivation Path Data | ?                |

##### Other Chunks/Packets

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Message | bytes... | Message to Sign |          |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (65) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### INS_SIGN_PERSONAL_MESSAGE

#### Command

| Field | Type     | Content                | Expected    |
| ----- | -------- | ---------------------- | ----------- |
| CLA   | byte (1) | Application Identifier | 0xE0        |
| INS   | byte (1) | Instruction ID         | 0x08        |
| P1    | byte (1) | Payload desc           | 0x0 = first |
|       |          |                        | 0x80 = more |
|       |          |                        |             |
| P2    | byte (1) | ----                   | not used    |
| L     | byte (1) | Bytes in the payload   | (depends)   |

The first packet/chunk includes the derivation path but it can also include some bytes of the message to be signed.

All other packets/chunks contain data chunks that are described below

##### First Packet

| Field   | Type     | Content              | Expected         |
| ------- | -------- | -------------------- | ---------------- |
| Path[0] | byte (4) | Derivation Path Data | 0x8000002c (44') |
| Path[1] | byte (4) | Derivation Path Data | 0x8000003c (60') |
| Path[2] | byte (4) | Derivation Path Data | ?                |
| Path[3] | byte (4) | Derivation Path Data | ?                |
| Path[4] | byte (4) | Derivation Path Data | ?                |
| Msg size| byte (4) | Size of msg to sign  | ?                |
| Msg     | bytes... | Msg to Sign          |                  |

##### Other Chunks/Packets

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Msg     | bytes... | Msg to Sign     |          |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (65) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |


/** ******************************************************************************
 *  (c) 2018 - 2026 Zondax AG
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
 ******************************************************************************* */

import Zemu from "@zondax/zemu";
import { FilecoinApp } from "@zondax/ledger-filecoin";
import { models, defaultOptions, PATH } from "./common";

jest.setTimeout(180000);

const CLA = 0x06;
const CLA_ETH = 0xe0;
const CLA_BAD = 0x44;

const INS_GET_ADDR_SECP256K1 = 0x01;
const INS_SIGN_SECP256K1 = 0x02;
const INS_SIGN_ETH = 0x04;
const INS_SIGN_RAW_BYTES = 0x07;
const INS_BAD = 0x99;

const P1_INIT = 0x00;
const P1_ADD = 0x01;
const P1_LAST = 0x02;
const P1_BAD = 0x03;

const P1_ETH_FIRST = 0x00;
const P1_ETH_MORE = 0x80;

const P2_NONE = 0x00;

const SW_OK = 0x9000;
const SW_WRONG_LENGTH = 0x6700;
const SW_COMMAND_NOT_ALLOWED = 0x6986;
const SW_TX_NOT_INITIALIZED = 0x6987;
const SW_INVALID_P1P2 = 0x6b00;
const SW_INS_NOT_SUPPORTED = 0x6d00;
const SW_CLA_NOT_SUPPORTED = 0x6e00;

// Accept every status word we assert on, so a wrong-but-known code surfaces as a
// readable expectation failure instead of a TransportStatusError.
const ACCEPTED_STATUS = [
  SW_OK,
  SW_WRONG_LENGTH,
  SW_COMMAND_NOT_ALLOWED,
  SW_TX_NOT_INITIALIZED,
  SW_INVALID_P1P2,
  SW_INS_NOT_SUPPORTED,
  SW_CLA_NOT_SUPPORTED,
];

// m/44'/461'/0'/0/1 as five little-endian uint32 words, the layout extractHDPath
// memcpy's straight into hdPath.
const HDPATH = Buffer.from("2c000080cd010080000000800000000001000000", "hex");

// Arbitrary CBOR fragment. This suite never completes a transaction, so the
// payload only has to be non-empty.
const CHUNK = Buffer.from("8a0055018ec1", "hex");

// Zemu wraps the transport in a proxy that raises TransportError for any status
// word other than 0x9000, regardless of the accepted-status list handed to the
// underlying transport. This suite asserts on rejections, so unwrap it back into
// a plain status word.
async function sw(
  transport: any,
  cla: number,
  ins: number,
  p1: number,
  p2: number,
  data: Buffer,
): Promise<number> {
  try {
    const resp = await transport.send(cla, ins, p1, p2, data, ACCEPTED_STATUS);
    return resp.readUInt16BE(resp.length - 2);
  } catch (e: any) {
    if (typeof e?.statusCode === "number") {
      return e.statusCode;
    }
    throw e;
  }
}

// A well-formed transfer -- the same blob standard.test.ts signs. Unlike CHUNK
// above this has to parse, because the point is to reach a review.
const TX_BLOB = Buffer.from(
  "8a0058310396a1a3e4ea7a14d49985e661b22401d44fed402d1d0925b243c923589c0fbc7e32cd04e29ed78d15d37d3aaa3fe6da3358310386b454258c589475f7d16f5aac018a79f6c1169d20fc33921dd8b5ce1cac6c348f90a3603624f6aeb91b64518c2e80950144000186a01961a8430009c44200000040",
  "hex",
);

const hex = (v: number) => `0x${v.toString(16)}`;

describe("APDU state machine", function () {
  // One container per device: every assertion below is a pure APDU exchange, and
  // the sequence is ordered so each step leaves the state the next one needs.
  // Spinning up a simulator per assertion would starve the runner.
  test.concurrent.each(models)(
    "chunk sequencing is enforced for $name",
    async function (m) {
      const sim = new Zemu(m.path);
      try {
        await sim.start({ ...defaultOptions, model: m.name });
        const t = sim.getTransport();
        const check = (actual: number, expected: number, what: string) =>
          expect(`${what} -> ${hex(actual)}`).toEqual(
            `${what} -> ${hex(expected)}`,
          );

        // --- device idle: nothing may be appended to a flow that never started ---
        check(
          await sw(t, CLA, INS_SIGN_SECP256K1, P1_ADD, P2_NONE, CHUNK),
          SW_TX_NOT_INITIALIZED,
          "add without init",
        );
        check(
          await sw(t, CLA, INS_SIGN_SECP256K1, P1_LAST, P2_NONE, CHUNK),
          SW_TX_NOT_INITIALIZED,
          "last without init",
        );
        check(
          await sw(t, CLA, INS_SIGN_RAW_BYTES, P1_ADD, P2_NONE, CHUNK),
          SW_TX_NOT_INITIALIZED,
          "raw-bytes add without init",
        );
        check(
          await sw(t, CLA_ETH, INS_SIGN_ETH, P1_ETH_MORE, P2_NONE, CHUNK),
          SW_TX_NOT_INITIALIZED,
          "eth continuation without a first chunk",
        );

        // --- dispatcher rejects malformed requests ---
        check(
          await sw(t, CLA, INS_SIGN_SECP256K1, P1_BAD, P2_NONE, CHUNK),
          SW_INVALID_P1P2,
          "unknown payload type",
        );
        check(
          await sw(t, CLA, INS_SIGN_SECP256K1, P1_INIT, 0x01, HDPATH),
          SW_INVALID_P1P2,
          "non-zero p2",
        );
        check(
          await sw(t, CLA, INS_BAD, 0x00, P2_NONE, CHUNK),
          SW_INS_NOT_SUPPORTED,
          "unknown instruction",
        );
        check(
          await sw(t, CLA_BAD, INS_SIGN_SECP256K1, P1_INIT, P2_NONE, HDPATH),
          SW_CLA_NOT_SUPPORTED,
          "unknown class",
        );

        // --- Filecoin instructions derive a Filecoin key, so the Ethereum class
        // must not reach them (0x02 is excluded: it is INS_GET_ADDR_ETH under
        // CLA_ETH and never enters the Filecoin switch) ---
        check(
          await sw(t, CLA_ETH, INS_SIGN_RAW_BYTES, P1_INIT, P2_NONE, HDPATH),
          SW_CLA_NOT_SUPPORTED,
          "raw-bytes under the eth class",
        );
        // P1 is 0x01 rather than 0x00 on purpose: zxlib's handle_generic_apdu
        // answers the reserved "E0 01 00 00" get-device-info probe before
        // handleApdu runs, so that exact header never reaches the class check.
        check(
          await sw(t, CLA_ETH, INS_GET_ADDR_SECP256K1, 0x01, P2_NONE, HDPATH),
          SW_CLA_NOT_SUPPORTED,
          "fil get address under the eth class",
        );

        // One payload byte: past the OFFSET_DATA guard, short of the five uint32
        // words extractHDPath needs. The state is claimed only after the path is
        // accepted, so this must leave the device idle rather than receiving.
        check(
          await sw(
            t,
            CLA,
            INS_SIGN_SECP256K1,
            P1_INIT,
            P2_NONE,
            Buffer.from([0x00]),
          ),
          SW_WRONG_LENGTH,
          "truncated hd path",
        );
        check(
          await sw(t, CLA, INS_SIGN_SECP256K1, P1_ADD, P2_NONE, CHUNK),
          SW_TX_NOT_INITIALIZED,
          "add after a rejected init",
        );

        // --- a flow is now in progress and owns the device ---
        check(
          await sw(t, CLA, INS_SIGN_SECP256K1, P1_INIT, P2_NONE, HDPATH),
          SW_OK,
          "init",
        );
        check(
          await sw(t, CLA, INS_SIGN_SECP256K1, P1_INIT, P2_NONE, HDPATH),
          SW_COMMAND_NOT_ALLOWED,
          "second init cannot restart a flow in progress",
        );
        check(
          await sw(t, CLA, INS_GET_ADDR_SECP256K1, 0x00, P2_NONE, HDPATH),
          SW_COMMAND_NOT_ALLOWED,
          "get address while receiving",
        );
        check(
          await sw(t, CLA, INS_SIGN_RAW_BYTES, P1_INIT, P2_NONE, HDPATH),
          SW_COMMAND_NOT_ALLOWED,
          "raw-bytes init while a fil flow is receiving",
        );
        check(
          await sw(t, CLA_ETH, INS_SIGN_ETH, P1_ETH_FIRST, P2_NONE, CHUNK),
          SW_COMMAND_NOT_ALLOWED,
          "eth first chunk while a fil flow is receiving",
        );

        // Rejecting those concurrent commands must not have disturbed the flow
        // they were competing with.
        check(
          await sw(t, CLA, INS_SIGN_SECP256K1, P1_ADD, P2_NONE, CHUNK),
          SW_OK,
          "add after init",
        );

        // --- an unrelated error must abort a half-received transaction ---
        // The buffered chunks were accepted under the HD path that INIT
        // installed, so an aborted flow must not be resumable against a new one.
        // Only APDU_CODE_OK and COMMAND_NOT_ALLOWED preserve the state; this pins
        // that split.
        check(
          await sw(t, CLA, INS_SIGN_SECP256K1, P1_BAD, P2_NONE, CHUNK),
          SW_INVALID_P1P2,
          "error during receive",
        );
        check(
          await sw(t, CLA, INS_SIGN_SECP256K1, P1_ADD, P2_NONE, CHUNK),
          SW_TX_NOT_INITIALIZED,
          "add after an aborted flow",
        );
      } finally {
        await sim.close();
      }
    },
  );

  // The assertions above all live in the receiving phase and never put anything
  // on screen. This covers what nothing else did: that a review hands the device
  // back once the user answers it, so a second transaction still gets through.
  //
  // The lock is zxlib's view_review_is_pending() rather than state this app
  // keeps, and it is checked at the top of handleApdu before any instruction is
  // dispatched -- so any status word other than 0x6986 below proves it was
  // released. The failure this guards against is a lock that arms but never
  // releases, leaving the app answering 0x6986 to everything until it is
  // restarted. Every other sign test here approves once and then closes the
  // simulator, so none of them would notice.
  //
  // Reuses the sign_basic goldens: same transaction, same review screens, so no
  // new snapshots.
  test.concurrent.each(models)(
    "a review hands the device back for $name",
    async function (m) {
      const sim = new Zemu(m.path);
      try {
        await sim.start({ ...defaultOptions, model: m.name });
        const app = new FilecoinApp(sim.getTransport());
        const t = sim.getTransport();
        const check = (actual: number, expected: number, what: string) =>
          expect(`${what} -> ${hex(actual)}`).toEqual(
            `${what} -> ${hex(expected)}`,
          );

        // Not awaited: sign only settles once the user answers the review.
        const signatureRequest = app.sign(PATH, TX_BLOB);
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
        await sim.compareSnapshotsAndApprove(
          ".",
          `${m.prefix.toLowerCase()}-sign_basic`,
        );
        await expect(signatureRequest).resolves.toBeDefined();

        // A plain request is served again.
        check(
          await sw(t, CLA, INS_GET_ADDR_SECP256K1, 0x00, P2_NONE, HDPATH),
          SW_OK,
          "get address once the review has been approved",
        );

        // And a fresh signing flow is accepted, which is the case that matters:
        // two transactions in a row must both get through.
        check(
          await sw(t, CLA, INS_SIGN_SECP256K1, P1_INIT, P2_NONE, HDPATH),
          SW_OK,
          "sign init once the review has been approved",
        );
        check(
          await sw(t, CLA, INS_SIGN_SECP256K1, P1_ADD, P2_NONE, CHUNK),
          SW_OK,
          "sign add once the review has been approved",
        );
      } finally {
        await sim.close();
      }
    },
  );
});

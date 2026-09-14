/** ******************************************************************************
 *  (c) 2026 Zondax AG
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
// @ts-ignore
import { FilecoinApp } from "@zondax/ledger-filecoin";
import { ec } from "elliptic";

import {
  defaultOptions,
  ETH_PATH,
  EXPECTED_PUBLIC_KEY,
  models,
} from "./common";

jest.setTimeout(180000);

const nanoX = models.find((model) => model.name === "nanox")!;
const EIP1559_ERC20 = Buffer.from(
  "02f87082013a80843b9aca00850d8c7b50e68303d09094eb466342c4d449bc9f53a865d5cb90586f40521580b844a9059cbb0000000000000000000000004e83362442b8d1bec281594cea3050c8eb01311c00000000000000000000000000000000000000000000000000000000075bca00c0",
  "hex",
);
const EIP1559_ERC20_WITH_NATIVE_VALUE = Buffer.from(
  "02f87882013a80843b9aca00850d8c7b50e68303d09094eb466342c4d449bc9f53a865d5cb90586f405215880de0b6b3a7640000b844a9059cbb0000000000000000000000004e83362442b8d1bec281594cea3050c8eb01311c00000000000000000000000000000000000000000000000000000000075bca00c0",
  "hex",
);

function expectValidSignature(
  transaction: Buffer,
  response: { r: string; s: string },
) {
  const sha3 = require("js-sha3");
  const signature = {
    r: Buffer.from(response.r, "hex"),
    s: Buffer.from(response.s, "hex"),
  };
  expect(
    new ec("secp256k1").verify(
      sha3.keccak256(transaction),
      signature,
      Buffer.from(EXPECTED_PUBLIC_KEY, "hex"),
      "hex",
    ),
  ).toEqual(true);
}

describe("Security regressions", () => {
  test("clear-signs an EIP-1559 ERC-20 transfer without dereferencing gasPrice", async () => {
    const sim = new Zemu(nanoX.path);
    try {
      await sim.start({ ...defaultOptions, model: nanoX.name });
      const app = new FilecoinApp(sim.getTransport());
      const signatureRequest = app.signETHTransaction(
        ETH_PATH,
        EIP1559_ERC20.toString("hex"),
        null,
      );

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", "x-security-erc20-eip1559");

      expectValidSignature(EIP1559_ERC20, await signatureRequest);
    } finally {
      await sim.close();
    }
  });

  test("requires blind signing when an ERC-20 transfer also carries native FIL", async () => {
    const sim = new Zemu(nanoX.path);
    try {
      await sim.start({ ...defaultOptions, model: nanoX.name });
      const app = new FilecoinApp(sim.getTransport());
      await sim.toggleBlindSigning();
      const signatureRequest = app.signETHTransaction(
        ETH_PATH,
        EIP1559_ERC20_WITH_NATIVE_VALUE.toString("hex"),
        null,
      );

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(
        ".",
        "x-security-erc20-native-value",
        true,
        0,
        1500,
        true,
      );

      expectValidSignature(
        EIP1559_ERC20_WITH_NATIVE_VALUE,
        await signatureRequest,
      );
    } finally {
      await sim.close();
    }
  });
});

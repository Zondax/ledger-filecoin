/** ******************************************************************************
 *  (c) 2018 - 2022 Zondax AG
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
import * as secp256k1 from "secp256k1";
import { models, defaultOptions, PATH_TESTNET } from "./common";
import * as multisigData from "./multisig.json";
import { getDigest } from "./utils";

const TEST_DATA = [
  {
    name: "multisig_create",
    op: multisigData.create.cbor,
  },
  {
    name: "multisig_propose",
    op: multisigData.propose.cbor,
  },
  {
    name: "multisig_approve",
    op: multisigData.approve.cbor,
  },
  {
    name: "multisig_cancel",
    op: multisigData.cancel.cbor,
  },
];

jest.setTimeout(90000);

describe.each(models)("Multisig", function (m) {
  test.concurrent.each(TEST_DATA)(
    `Multisig extended params: $name for ${m.name}`,
    async function ({ name, op }) {
      const sim = new Zemu(m.path);
      try {
        await sim.start({ ...defaultOptions, model: m.name });
        const app = new FilecoinApp(sim.getTransport());

        const testcase = `${m.prefix.toLowerCase()}-sign-${name}`;

        // Put the app in expert mode
        await sim.toggleExpertMode();

        const txBlob = Buffer.from(op, "hex");

        const pkResponse = await app.getAddressAndPubKey(PATH_TESTNET);
        console.log(pkResponse);

        // do not wait here so we can get snapshots and interact with the app
        const signatureRequest = app.sign(PATH_TESTNET, txBlob);

        // Wait until we are not in the main menu
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
        await sim.compareSnapshotsAndApprove(".", testcase);

        let resp = await signatureRequest;
        console.log(resp, m.name, name);

        // Verify signature
        const pk = Uint8Array.from(pkResponse.compressed_pk);
        const digest = getDigest(txBlob);
        const signature = secp256k1.signatureImport(
          Uint8Array.from(resp.signature_der),
        );
        const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
        expect(signatureOk).toEqual(true);
      } finally {
        await sim.close();
      }
    },
  );
});

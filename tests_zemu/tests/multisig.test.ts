/** ******************************************************************************
 *  (c) 2020 Zondax GmbH
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

import Zemu, {DEFAULT_START_OPTIONS, DeviceModel} from "@zondax/zemu";
// @ts-ignore
import FilecoinApp from "@zondax/ledger-filecoin";
import {getDigest} from "./utils";
import * as secp256k1 from "secp256k1";
import { APP_SEED, models, defaultOptions } from './common'
import * as multisigData from "./multisig.json"

const TEST_DATA = [
  {
    name: 'multisig_create',
    op: multisigData.create.cbor,
  },
  {
    name: 'multisig_propose',
    op: multisigData.propose.cbor,
  },
  {
    name: 'multisig_approve',
    op: multisigData.approve.cbor,
  },
  {
    name: 'multisig_cancel',
    op: multisigData.cancel.cbor,
  }
]



describe.each(models)('Multisig', function (m) {
  test.each(TEST_DATA)('Multisig extended params', async function ({name, op}) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      const testcase = `${m.prefix.toLowerCase()}-sign-${name}`

      // Put the app in expert mode
      await sim.clickRight();
      await sim.clickBoth();
      await sim.clickLeft();

      const path = "m/44'/461'/0'/0/1";

      const txBlob = Buffer.from(op, 'hex');

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here so we can get snapshots and interact with the app
      const signatureRequest = app.sign(path, txBlob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndApprove(".", testcase)

      let resp = await signatureRequest;
      console.log(resp, m.name, name)

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");
    } finally {
      await sim.close();
    }
  });
})

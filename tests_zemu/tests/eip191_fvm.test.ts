/** ******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
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
import Zemu, {
  ButtonKind,
  TouchNavigation,
  ClickNavigation,
  isTouchDevice,
} from "@zondax/zemu";
// @ts-ignore
import { FilecoinApp } from "@zondax/ledger-filecoin";
import { defaultOptions, models, PATH, EIP191_FVM_PREFIX } from "./common";
import { getBlakeHash } from "./utils";
import * as secp256k1 from "secp256k1";
import { getTouchElement } from "@zondax/zemu/dist/buttons";
import { IButton } from "@zondax/zemu/dist/types";

jest.setTimeout(90000);

// @ts-ignore
const blake = require("blakejs");

const SIGN_TEST_DATA = [
  {
    name: "personal_sign_msg",
    message: Buffer.from("Hello World!", "utf8"),
    blind: false,
  },
  {
    name: "personal_sign_big_msg",
    message: Buffer.from(
      "Just a big dummy message to be sign. To test if we are parsing the chunks in the right way. By: Zondax",
      "utf8",
    ),
    blind: false,
  },
  {
    name: "personal_sign_non_printable_msg",
    message: Buffer.from("\x00Hello World!", "utf8"),
    blind: true,
  },
];

describe.each(models)("EIP191", function (m) {
  test.concurrent.each(SIGN_TEST_DATA)(
    `sign transaction: $name for ${m.name}`,
    async function (data) {
      const sim = new Zemu(m.path);
      try {
        await sim.start({ ...defaultOptions, model: m.name });
        const app = new FilecoinApp(sim.getTransport());

        // Get public key and address
        const publicKeyResponse = await app.getAddressAndPubKey(PATH);

        // Enable blind signing if required
        if (data.blind) {
          await sim.toggleBlindSigning();
        }

        // Start signature request
        const signatureRequest = app.signPersonalMessageFVM(PATH, data.message);

        // Wait until we are not in the main menu and approve
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
        await sim.compareSnapshotsAndApprove(
          ".",
          `${m.prefix.toLowerCase()}-fvm-${data.name}`,
          true,
          0,
          1500,
          data.blind,
        );

        const signatureResponse = await signatureRequest;

        // Construct EIP-191 message format: "\x19Filecoin Signed Message:\n" + len + message
        const msgLengthString = String(data.message.length);
        const eip191Message = Buffer.concat([
          EIP191_FVM_PREFIX,
          Buffer.from(msgLengthString, "utf8"),
          data.message,
        ]);
        const messageHash = getBlakeHash(eip191Message);

        // Verify signature
        const publicKey = Uint8Array.from(publicKeyResponse.compressed_pk);
        const signature = secp256k1.signatureImport(
          Uint8Array.from(signatureResponse.signature_der),
        );

        const isSignatureValid = secp256k1.ecdsaVerify(
          signature,
          Uint8Array.from(messageHash),
          publicKey,
        );

        expect(isSignatureValid).toEqual(true);
      } finally {
        await sim.close();
      }
    },
  );
});

describe.each(models)("EIP191 no bls", function (m) {
  // only test personal_sign_non_printable_msg
  test.only.each(SIGN_TEST_DATA.filter(d => d.name === 'personal_sign_non_printable_msg'))(
    `sign no bls transaction $name for ${m.name}`,
    async function (data) {
      const sim = new Zemu(m.path);
      try {
        await sim.start({ ...defaultOptions, model: m.name });
        const app = new FilecoinApp(sim.getTransport());

        // Get public key and address
        const publicKeyResponse = await app.getAddressAndPubKey(PATH);

        // Start signature request, should fail because blind signing is not enabled
        const signNonBls = app.signPersonalMessageFVM(PATH, data.message);

        await Zemu.sleep(500);
  
        // Wait until we are not in the main menu
        console.log("STEP 0");
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
        console.log("STEP 1");

        let nav = undefined;
        if (isTouchDevice(m.name)) {
          const rejectButton: IButton = getTouchElement(m.name, ButtonKind.RejectButton)
          nav = new TouchNavigation(m.name, [ButtonKind.RejectButton]);
          nav.schedule[0].button = rejectButton;
        } else {
          nav = new ClickNavigation([0]);
        }


        await sim.navigate(
          ".",
          `${m.prefix.toLowerCase()}-fvm-no-bls-${data.name}`,
          nav.schedule,
        );

        await expect(signNonBls).rejects.toThrow("Data is invalid : Blindsign Mode Required");

        sim.clearTransportError();
        await sim.toggleBlindSigning();

        const signatureRequest = app.signPersonalMessageFVM(PATH, data.message);

        // Wait until we are not in the main menu and approve
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
        await sim.compareSnapshotsAndApprove(
          ".",
          `${m.prefix.toLowerCase()}-fvm-no-bls-${data.name}`,
          true,
          2,
          1500,
          data.blind,
        );

        const signatureResponse = await signatureRequest;

        // Construct EIP-191 message format: "\x19Filecoin Signed Message:\n" + len + message
        const msgLengthString = String(data.message.length);
        const eip191Message = Buffer.concat([
          EIP191_FVM_PREFIX,
          Buffer.from(msgLengthString, "utf8"),
          data.message,
        ]);
        const messageHash = getBlakeHash(eip191Message);

        // Verify signature
        const publicKey = Uint8Array.from(publicKeyResponse.compressed_pk);
        const signature = secp256k1.signatureImport(
          Uint8Array.from(signatureResponse.signature_der),
        );

        const isSignatureValid = secp256k1.ecdsaVerify(
          signature,
          Uint8Array.from(messageHash),
          publicKey,
        );

        expect(isSignatureValid).toEqual(true);
      } finally {
        await sim.close();
      }
    },
  );
});


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
import FilecoinApp from "@zondax/ledger-filecoin";
import {getDigest} from "./utils";
import * as secp256k1 from "secp256k1";
import { models, defaultOptions, PATH } from './common'


describe('Standard', function () {
  test.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path);
    try {
      console.log("model: ", m.name)
      await sim.start({...defaultOptions, model: m.name,});
    } finally {
      await sim.close();
    }
  });

  test.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, [1, 0, 0, 4, -5])
    } finally {
      await sim.close();
    }
  });

  test.each(models)('get app version', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());
      const resp = await app.getVersion();

      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");
      expect(resp).toHaveProperty("test_mode");
      expect(resp).toHaveProperty("major");
      expect(resp).toHaveProperty("minor");
      expect(resp).toHaveProperty("patch");
    } finally {
      await sim.close();
    }
  });

  test.each(models)('get address', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      const resp = await app.getAddressAndPubKey("m/44'/461'/5'/0/3");

      console.log(resp)

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const expected_address_string = "f1mk3zcefvlgpay4f32c5vmruk5gqig6dumc7pz6q";
      const expected_pk = "0425d0dbeedb2053e690a58e9456363158836b1361f30dba0332f440558fa803d056042b50d0e70e4a2940428e82c7cea54259d65254aed4663e4d0cffd649f4fb";

      expect(resp.addrString).toEqual(expected_address_string);
      expect(resp.compressed_pk.toString('hex')).toEqual(expected_pk);

    } finally {
      await sim.close();
    }
  });

  test.each(models)('show address', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      // Derivation path. First 3 items are automatically hardened!
      const respRequest = app.showAddressAndPubKey("m/44'/461'/5'/0/3");

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-show_address`)

      const resp = await respRequest;

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const expected_address_string = "f1mk3zcefvlgpay4f32c5vmruk5gqig6dumc7pz6q";
      const expected_pk = "0425d0dbeedb2053e690a58e9456363158836b1361f30dba0332f440558fa803d056042b50d0e70e4a2940428e82c7cea54259d65254aed4663e4d0cffd649f4fb";

      expect(resp.addrString).toEqual(expected_address_string);
      expect(resp.compressed_pk.toString('hex')).toEqual(expected_pk);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign basic & verify', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      const txBlob = Buffer.from(
        "8a0058310396a1a3e4ea7a14d49985e661b22401d44fed402d1d0925b243c923589c0fbc7e32cd04e29ed78d15d37d3aaa3fe6da3358310386b454258c589475f7d16f5aac018a79f6c1169d20fc33921dd8b5ce1cac6c348f90a3603624f6aeb91b64518c2e80950144000186a01961a8430009c44200000040",
        "hex",
      );

      const pkResponse = await app.getAddressAndPubKey(PATH);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(PATH, txBlob);
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_basic`)

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      // Verify signature
      const pk = Uint8Array.from(pkResponse.compressed_pk)
      const digest = getDigest(txBlob);
      const signature = secp256k1.signatureImport(Uint8Array.from(resp.signature_der));
      const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
      expect(signatureOk).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign basic - invalid', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      let invalidMessage = Buffer.from(
        "890055026d21137eb4c4814269e894d296cf6500e43cd7145502e0c7c75f82d55e5ed55db28033630df4274a984f0144000186a0430009c41961a80040",
        "hex",
      );
      invalidMessage = Buffer.concat([invalidMessage, Buffer.from("1")]);

      const pkResponse = await app.getAddressAndPubKey(PATH);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureResponse = await app.sign(PATH, invalidMessage);
      console.log(signatureResponse);

      expect(signatureResponse.return_code).toEqual(0x6984);
      expect(signatureResponse.error_message).toEqual("Data is invalid : Unexpected data type");
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign proposal', async function (m) {
    const sim = new Zemu(m.path);
    try {
      console.log("model: ", m.name)
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      const txBlob = Buffer.from(
        "8a004300ec075501dfe49184d46adc8f89d44638beb45f78fcad259001401a000f4240430009c4430009c402581d845501dfe49184d46adc8f89d44638beb45f78fcad2590430003e80040",
        "hex",
      );

      const pkResponse = await app.getAddressAndPubKey(PATH);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");
      console.log("No errors retriving address")

      // do not wait here so we can get snapshots and interact with the app
      const signatureRequest = app.sign(PATH, txBlob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_proposal`)

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      // Verify signature
      const pk = Uint8Array.from(pkResponse.compressed_pk)
      const digest = getDigest(txBlob);
      const signature = secp256k1.signatureImport(Uint8Array.from(resp.signature_der));
      const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
      expect(signatureOk).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign proposal expert ', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      // Put the app in expert mode
      await sim.clickRight();
      await sim.clickBoth();
      await sim.clickLeft();

      const txBlob = Buffer.from(
        "8a004300ec075501dfe49184d46adc8f89d44638beb45f78fcad259001401a000f4240430009c4430009c402581d845501dfe49184d46adc8f89d44638beb45f78fcad2590430003e80040",
        "hex",
      );

      const pkResponse = await app.getAddressAndPubKey(PATH);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here so we can get snapshots and interact with the app
      const signatureRequest = app.sign(PATH, txBlob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_proposal_expert`)

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      // Verify signature
      const pk = Uint8Array.from(pkResponse.compressed_pk)
      const digest = getDigest(txBlob);
      const signature = secp256k1.signatureImport(Uint8Array.from(resp.signature_der));
      const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
      expect(signatureOk).toEqual(true);
    } finally {
      await sim.close();
    }
  });


  test.each(models)('sign proposal -- unsupported method', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      const invalidMessage = Buffer.from(
        "8a004300ec075501dfe49184d46adc8f89d44638beb45f78fcad259001401a000f4240430009c4430009c432581d845501dfe49184d46adc8f89d44638beb45f78fcad2590430003e80040",
        "hex",
      );

      const pkResponse = await app.getAddressAndPubKey(PATH);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureResponse = await app.sign(PATH, invalidMessage);
      console.log(signatureResponse);

      expect(signatureResponse.return_code).toEqual(0x6984);
      expect(signatureResponse.error_message).toEqual("Data is invalid : Unexpected data type");

    } finally {
      await sim.close();
    }
  });

/*
  Should reject BLS signature
  test.each(models)('try signing using BLS - fail', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());
      const path = "m/44'/461'/0'/0/1";
      const txBlob = Buffer.from(
        "8a00583103a7726b038022f75a384617585360cee629070a2d9d28712965e5f26ecc40858382803724ed34f2720336f09db631f074583103ad58df696e2d4e91ea86c881e938ba4ea81b395e12797b84b9cf314b9546705e839c7a99d606b247ddb4f9ac7a3414dd0144000186a01961a8420000430009c40040",
        "hex",
      );
      // do not wait here so we can get snapshots and interact with the app
      const signatureRequest = app.sign(path, txBlob);
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      let resp = await signatureRequest;
      console.log(resp);
      expect(resp.return_code).toEqual(0x6984);
      expect(resp.error_message).toEqual("Data is invalid : Unexpected data type");
    } finally {
      await sim.close();
    }
  });*/

  test.each(models)('test change owner', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name, });
      const app = new FilecoinApp(sim.getTransport());

      const txBlob = Buffer.from(
        "8a0044008bcb534400f59c53004000404017454400f59c53",
        "hex",
      );

      const pkResponse = await app.getAddressAndPubKey(PATH);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here so we can get snapshots and interact with the app
      const signatureRequest = app.sign(PATH, txBlob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-change_owner`)

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      // Verify signature
      const pk = Uint8Array.from(pkResponse.compressed_pk)
      const digest = getDigest(txBlob);
      const signature = secp256k1.signatureImport(Uint8Array.from(resp.signature_der));
      const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
      expect(signatureOk).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('transfer using protocol 4 addresses', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      const txBlob = Buffer.from(
        "8a0056040ad4224267c4ab4a184bd1aa066b3361e70efbbeaf56040ad4224267c4ab4a184bd1aa066b3361e70efbbeaf0144000186a01961a84200014200010040",
        "hex",
      );

      const pkResponse = await app.getAddressAndPubKey(PATH);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(PATH, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_transfer_protocol4`)

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      // Verify signature
      const pk = Uint8Array.from(pkResponse.compressed_pk)
      const digest = getDigest(txBlob);
      const signature = secp256k1.signatureImport(Uint8Array.from(resp.signature_der));
      const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
      expect(signatureOk).toEqual(true);
    } finally {
      await sim.close();
    }
  });
})

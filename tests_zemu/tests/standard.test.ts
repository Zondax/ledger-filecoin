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

import Zemu, { zondaxMainmenuNavigation, ButtonKind, TouchNavigation, ClickNavigation, isTouchDevice } from '@zondax/zemu'

// @ts-ignore
import FilecoinApp from "@zondax/ledger-filecoin";
import { getDigest } from "./utils";
import * as secp256k1 from "secp256k1";
import { models, defaultOptions, PATH } from './common'
import { IButton, SwipeDirection } from '@zondax/zemu/dist/types';

jest.setTimeout(600000)

describe('Standard', function () {
  test.concurrent.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path);
    try {
      console.log("model: ", m.name)
      await sim.start({ ...defaultOptions, model: m.name, });
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const nav = zondaxMainmenuNavigation(m.name, [1, 0, 0, 4, -5])
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, nav.schedule)
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)('get app version', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name, });
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

  test.concurrent.each(models)('get address', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name, });
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

  test.concurrent.each(models)('show address', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Confirm' : '',
        approveAction: ButtonKind.DynamicTapButton,
      })
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

  test.concurrent.each(models)('sign basic & verify', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name, });
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

  test.concurrent.each(models)('sign basic - invalid', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name, });
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

  test.concurrent.each(models)('sign proposal expert ', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name, });
      const app = new FilecoinApp(sim.getTransport());

      // Put the app in expert mode
      await sim.toggleExpertMode();

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


  test.concurrent.each(models)('sign proposal -- unsupported method', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name, });
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
    test.concurrent.each(models)('try signing using BLS - fail', async function (m) {
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

  test.concurrent.each(models)('test change owner', async function (m) {
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

  test.concurrent.each(models)('transfer using protocol 4 addresses', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name, });
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

  test.concurrent.each(models)('RawBytes', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name, });
      const app = new FilecoinApp(sim.getTransport());

      // Put the app in expert mode
      await sim.toggleBlindSigning();

      // sign 1KB of data
      const raw_bytes = Buffer.from("ab11c412ff5f6fafc466e856f67eb20ad85ef754ad1b7c5d4120ffe95dcd94bd1079f1a89a575d284422825f1aaeb099439bc60e6537e3c939a3a5f0e108d372be73d388da351c11bfc5a20a316051fcd52b4a6d003cd1eef171ba197cfbf8d245f705d65ee0c82fa74e4d3ee1f918a496a0244fb342b7ea0a836e522ba3519001866edde3207af56ad45177433ceb0290e0b55e0584b4c799a7646805d50e885e95e89209d5b223d82001be1c85c881ec6c5bd21bcfceb286c12fdc1f28feaaaa13853655c24f6ef5c640c222ba8ed161718d535786867481fb96bc1720be4b63438d72ba559cb0c72485d1fb6543bc6c684d358aa7cfc1877031600c6efb0f90e5224951205e276cbbd3876953e92a522e26d22a75b0417b2971866a839c03825df7e06de380e00ba7599c59a01165a0ac95d636cc63d09f095df058a273aa4067e9dbeeb7d28ba62519c34c485c9389a485d90f6c47698260fc43b5d2fb88794c34f129fd2861a310c74238f12cd7c84b4f8df19faf05a0756e8b5261b48ee45929f9cfc33c8cedb69029af312a544b216ea8fc33a10cd7188d58591c8a22b2ee3ab6816fe45e080c4f1733ea2a71627cbc90133cecd8eae635e0d522731ee1992a09f411a424bc48ae54cfebcdb442d34ef8e42b1cd9212fdda322baed3569437e1106b67a25d064b0d96a1150a4ea866e4849eb646574a5e3c0d4d6efca09eef7feaf540a6eda9c886d92018b2afbf64d9c077c83f23f45529f826a51b575432c6fa0c7849799c3e9ba5a0f4d71b93a12b72a9d06238c686561cd952a2a50e2c516f3fc1b60e94365dbc883a8a47a0214a6df74390c9963836e6d1099bc16da0a6caf07f0962b945ef225930bd6131fe344ff7fcac9f0181a0a24940146b03b79a3de67b92fe592183258e939685d47089e6f9228b169952aabb45f3ad369b1d557099ce97b6092f2e0bd6122c2479fed1a2427c8fd763a93587795f38a391782b0dadf857a3a8d896940c94cef4183d3ff52f26af4957736955db70d668f524285d091313ffc9b807e0502edc6fbc3f1d6e76350a0c3d78fc6cdc6ae36bd2b9dccb3b4e7734c8d91a2c883390953429fd9dd185a81bfa3ac147d86342ac3b227eff6ac0c2904596076b845a3267b1b472e8bbb429575fb280ec82718734ceb2b07e8c998b42cad224c98cc56aa5ca3a9159e8bf3604f4f56b2350befc00cca8e1a1aecb3dbb64c9536ec557204dfd3ee68ee16b641c41e75c4f97266ed4c5f78b5f8fd7ff11eb8c5db201f85b3904f13931bbead263a00e85d1086340bb4a2fb6fd139b793d4a7540b3dbf2495f7d08f8821759bde65817aa08fa1424101639fbfb6c4f91961da1372bccb127afc627d352f9d9d2faa5a9176be55274b53dc04b94174b6b7aa52955939cf14970d31e03ea60cb2cdc99e422f232a4052", 'hex')
      const prefix = Buffer.from("Filecoin Sign Bytes:\n");
      const txBlob = Buffer.concat([prefix, raw_bytes]);
      console.log("Tx: ", txBlob.toString('hex'));
      const d = getDigest(txBlob);
      const print = Buffer.from(d)
      console.log("digest: ", print.toString('hex'));


      const pkResponse = await app.getAddressAndPubKey(PATH);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRawBytes(PATH, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_raw_bytes`, true, 0, 1500, true)

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      // Verify signature
      const pk = Uint8Array.from(pkResponse.compressed_pk);
      const digest = getDigest(txBlob);

      const signature = secp256k1.signatureImport(Uint8Array.from(resp.signature_der));
      const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
      expect(signatureOk).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)('InvokeEVM_ERC20Transfer', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name, });
      const app = new FilecoinApp(sim.getTransport());

      const txBlob = Buffer.from(
        "8a0056040a60e1773636cf5e4a227d9ac24f20feca034ee25a5501f12b13543456cf32f3918bfdcfe636cd0cb5730d18ce401a01cd049d44000325f844000311821ae525aa1558465844a9059cbb000000000000000000000000ff000000000000000000000000000000001c048500000000000000000000000000000000000000000000000000005af3107a4000",
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

      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_erc20_transfer`)

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

  test.concurrent.each(models)('InvokeEVM', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name, });
      const app = new FilecoinApp(sim.getTransport());

      const txBlob = Buffer.from(
        "8A0056040AEA71F8DC046717B8B14C18005186D03495A0E49255011EAF1C8A4BBFEEB0870B1745B1F57503470B71160349000DE0B6B3A76400001A0022F6F34400018A9D440001867F1AE525AA1540",
        "hex",
      );

      const pkResponse = await app.getAddressAndPubKey(PATH);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      const signNonExpert = await app.sign(PATH, txBlob);
      console.log(signNonExpert);
      expect(signNonExpert.return_code).toEqual(0x6984)
      expect(signNonExpert.error_message).toEqual("Data is invalid : ExpertModeRequired");

      await Zemu.sleep(500);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      let nav = undefined;
      if (isTouchDevice(m.name)) {
        const okButton: IButton = {
          x: 200,
          y: 540,
          delay: 0.25,
          direction: SwipeDirection.NoSwipe,
        };
        nav = new TouchNavigation(m.name, [
          ButtonKind.ConfirmYesButton,
        ]);
        nav.schedule[0].button = okButton;
      } else {
        nav = new ClickNavigation([1, 0]);
      }
      await sim.navigate('.', `${m.prefix.toLowerCase()}-invoke_evm`, nav.schedule);


      await sim.toggleExpertMode();

      // // do not wait here..
      const signatureRequest = app.sign(PATH, txBlob);
      // // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-invoke_evm`, true, 2)

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

  // https://github.com/Zondax/ledger-filecoin/issues/166
  test.concurrent.each(models.filter(m => m.name != "nanos"))('Issue #166', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      const txBlob = Buffer.from(
          "8A005502972DE5CB57E5208A9FEF1887B39B2BE0EBDA5FEE5501539A38D7116E30F44985EFF6E99A2D5FBADF951901401A044A58AB44000189DD44000185BF025901E88456040ADC451DCFCE6429224C835B09E60FFAD5EBBBC9F0401AE525AA155901C75901C4AC9650D800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000C0000000000000000000000000000000000000000000000000000000000000004443AEEEB2000000000000000000000000FF00000000000000000000000000000000023319000000000000000000000000000000000000000000000000000000000000000A000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000084F654B137000000000000000000000000FF000000000000000000000000000000000233190000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000003E800000000000000000000000000000000000000000000000000000000",
          "hex",
      );

      // // do not wait here..
      const signatureRequest = app.sign(PATH, txBlob);
      // // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-issue-166`)

      let resp = await signatureRequest;
      console.log(resp);
      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");
    } finally {
      await sim.close();
    }
  });

  // Test to cover issue https://github.com/Zondax/ledger-filecoin/issues/173
   test.concurrent.each(models)('Parse Bytes Params - issue #173', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      const txBlob = Buffer.from(
          "8a00550191519a1de64c30be61381ac8168aa411770d0984550178b407e26c1825b937b85d8e506f492beff267f81905a24200011a001776a74400019c634400019845004b68656c6c6f20776f726c64",
          "hex",
      );

      // // do not wait here..
      const signatureRequest = app.sign(PATH, txBlob);
      // // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-issue-173`)

      let resp = await signatureRequest;
      console.log(resp);
      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");
    } finally {
      await sim.close();
    }
  });
})

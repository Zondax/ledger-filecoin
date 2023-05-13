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
  test.concurrent.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path);
    try {
      console.log("model: ", m.name)
      await sim.start({...defaultOptions, model: m.name,});
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, [1, 0, 0, 4, -5])
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)('get app version', async function (m) {
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

  test.concurrent.each(models)('get address', async function (m) {
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

  test.concurrent.each(models)('show address', async function (m) {
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

  test.concurrent.each(models)('sign basic & verify', async function (m) {
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

  test.concurrent.each(models)('sign basic - invalid', async function (m) {
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

  test.concurrent.each(models)('sign proposal expert ', async function (m) {
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


  test.concurrent.each(models)('sign proposal -- unsupported method', async function (m) {
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

  test.concurrent.each(models)('RemoveDataCap', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      // The data to sign for this transaction is:
      // proposalID = 256
      // allowance_to_remove = 15_000_000
      // cliens_address = t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba
      const txBlob = Buffer.from("8319010058200000000000000000000000000000000000000000000000000000000000e4e1c055011eaf1c8a4bbfeeb0870b1745b1f57503470b7116", 'hex')

      const pkResponse = await app.getAddressAndPubKey(PATH);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRemoveDataCap(PATH, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_remove_datacap`)

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

  test.concurrent.each(models)('ClientDeal', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      // Put the app in expert mode
      await sim.clickRight();
      await sim.clickBoth();
      await sim.clickLeft();

      // cid: "QmS7ye6Ri2MfFzCkcUJ7FQ6zxDKuJ6J6B8k5PN7wzSR9sX\n"
      // piece_size = 100000
      // client := "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"
      // provider := "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy"
      // label: ["deal_label", true]
      // const start_epoch = 1715446709
      // const end_epoch = 1718125109
      // storage_price = 90000
      // provider_collateral = 50000
      // client_collateral = 80000"
      // verified_deal = true
      const txBlob = Buffer.from("8b782f516d53377965365269324d66467a436b63554a374651367a78444b754a364a3642386b35504e37777a53523973580a1a000186a055011eaf1c8a4bbfeeb0870b1745b1f57503470b71165501dfe49184d46adc8f89d44638beb45f78fcad2590826a6465616c5f6c6162656cf51a663fa3b51a6668823558200000000000000000000000000000000000000000000000000000000000015f905820000000000000000000000000000000000000000000000000000000000000c35058200000000000000000000000000000000000000000000000000000000000013880f5", 'hex')

      const pkResponse = await app.getAddressAndPubKey(PATH);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signClientDeal(PATH, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_client_deal`)

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
      await sim.start({...defaultOptions, model: m.name,});
      const app = new FilecoinApp(sim.getTransport());

      // sign 4KB of data
      const raw_bytes = Buffer.from("cf5e9a9195867c2bb835ae4cc3d61a8161dcfcfc21968d2882b693e9998591f7a2249b1f6a46e69c9d73ba91b97a1dc94770b577c515de8fdc16faf9bfc8184b66529e68982f90e145c25d0985665914f7d86b69256cc20f52593cadc381fd924c13c672559aba3ffd5e4899df4673c03480f1983bec6ad70a776d9164722e7646ee501f274401deba78ad788fd303b3c7024052b44a6f90bcc75605045e937641cc08900e04401f139f8353357b4d5389db5cc9a1ee2e9bacc9ff4aa2a8fc2775e55efd4cecfca38bc343ae49fb91a1a9d4cba775bd09366c8c34e30607c2bd530910d43e1b432fa68b9bee9d9279ca2c8df33ccc139ca9a9e2f14420cd17b086662b8af4107c5357f2e303b247333122b8044a0faf174a1ab937d858f699c7111568f5abe5cf31b0fbddc7b49fb0f4f0e8b6c07e01a5281078efe3b998236489a379bdcbdca5d4a924a66457fb1fd0025953af97ab98b2bc262404161752b0fcbb6f117f824b286ab0ebc02875f95e63ae9fe890cb6469a42fce79cc5ff6c8f0a9c0a40228425883b37bebe05e3e4d85d0032c89ca4cdf5b1e2344abdcfcc333b9b55b88461fe4592af622f24a0351f64f0f15a2e265e88597fccf036191514226e4ddca3a5e2d87543b11954151ec11867cdcb0640d6d3e78334d10e7ef592ae1aa1eb8579e04b616ca6506c72dea1b0428177a0569661755aeb1220d64e73e90903296c433b97460dbbd8cd08c2acea7592f66f3550cb32e06d6924f20abd02e4caf2eaf0eb4fc01c5467ca66b15bfe1afd94e05765758d9b4708e8e320d11e182d0d92633385f3899f00fc146e12300565498e526fc6de1a98a062e3ad31e738bb15d2a7995188b78ad4c465427408aa063678cdf1d3a4c6ff80b28b06850aaa0b5d40bae5d91e752835ceebef8a80c9bd7f6371447fb8f99a8abca5fb302289131031bf3329ec4fd62d22249f09f7a31a53592827818c54fe4ff2d68aea44d80c337e2650de67c9758b24d80ba45c9ba741d1b9ca02c68f4cd4e858512ea823831dc93fcace58b0fb6be2225199817fc0e0f035b10b89b02b3584e4f96fb2a2a0d668211cd58f1398a8a375f8a1e0d6e02406a81c5e8dcadddc6ff560b25f6bfacad4887fe2468a1dee7e6de7835383d2c0aecc8522e20d6da19ff5b60109f0a0a8483dfb648768b190a6837e9bf672b17072446a69e9880bea04de457214b52a5f914638bd3434306b00d959aa9bdee0545dc78bf1aa98192f7cc918e2d0994185dfc0a40c35ce7479604070193b88f9ea285b5b31b2dbe6ea5d28562d6d79c9ff92630c2ebaa0cd4694a59841a02fbe8bec66397d9e7b1643817dafa8b3799493811fa568aa5470155cf1cb76583abaa5248c918a7f037937040dce063393e341ab8f9ea2fa9f3b14304ce48e91c5cb0b7b4e4af8fa3f4d488f5b8f38d30f74353084a629e54ac83aa253f6688526a013c835652aa16728d533ab13c22513d9db120c6d2b0cc965ab2b48e973d793a3cc84ea13e697c7029cc85fa6e054d70d67f7999a6a653843c0b034b2b20de1aff7df7b90ace9644bb682ce3396a2e629c05c75669ecaf5da2dea6e089a226eedf8d7f522b0d22d00f3d4f044b796a1b7a12e4813d8f8c9ca2e09803d00a397023f8c6b22c8763a62b1d92f81dee5098acdb7ea53c7fec8dce69a365f69a06b90f6d4bacb5aa5a3f6f771d68e8e38f36355b055f3fb471fcb79187aefc7b3482fd30209a3da17b8fe30fdc42685c6a375318a0c2aeced8c20fa7f66dc0305b532c7dbe39cdfb543d55cc5a36193e1af9c096d73bb7aedc9475a17584ca6a020b27ed4584a97d6f887b3f65b5e0961f16771f7d69ce40fab6707a7c5f729860bc43378635493787bf7941bb252d8402a77899a8a5b50d38541960102a98200a0478bf64e4915e7c43cdf6a9ca62ba96f5ab872f21b12512c62038f059fef5f2d39f6d3696a5e31ba0130b827ff470f7f9c58ca90026ec0db2f3c7ef9ecbc8884791749d46a2d5501b7293b0717b867950fa23917883aecc40adfd4cfb470b80e6ededdc60a7102e595cee6ac553cc6dab9445ddf15c94a48eafccad6a24be145ca440602891eeeada703e048a6396da83c11ca7b01c8036ef08a61024e2612602b81cdb492cd1e3ca04058ddbe1679a04953cc97b8d22622b2ece1c249eae5f194434141ab40d9a44195ddac3bf9cfb8273c56523bb30ceb7057caaf45df193d588fb2dec4391bd16821663b799653fcbb79be87bdd949617fa146f553b1e96684d5e6b9c752a87d9e1e6eb6ee50a1bb38c9d944fb144dbc8a76680f356e75ed6c2f21ed5302b928a873b63ba8ca6de247cb5d2b49bc887c82f3a8aae1ae64a5791edb909f8fa89f8128f8e05d0070482a2c141a6aa018aa5ab48a68ac6390cb5d2881156f540ef8bdfbaf8c21d6a26f5f35497b1df5bbdf58e5b0901d22483054d51e1da47a82e150932e2f491a2d0cfbe5f336735da7cb43f8a4b5885518b1788e6df6bdc99351d4f3b2bfc830c84817f99fa31d00df8d09b906f232243b4fcca6d3ad20516e7ea9d8436e037084f3b4540fa062de16356f48e02bcf7a77a9e63305b7852319c2660ddc48f1e156abd0096fd0cf1980598c1403ec5ed123093d5dd425a8f38a961c59c05f390fb56046d0d5b0838f4edefbf75b4255b5880ddea155bfec5375fdae713035d29ba40301b4a38b347243ab88a7a2e6db4db06a9cbef6ca2e0eda6a9888758230412f6ebbcdbe20e29dc011847588a40fc89236bd9fd312e2bb2a194c8a8a1889c43282303b8ad8b80593d018f15aadf624d7adc9bcb25338696d89a07baaf4aa1647c642ce86bf88ff551dac3a7595a617348c97c64b4e5060edc727c265ed8f7c09de2242b20f1d838bea17f37e9027319b6933ba8439a8ee3d30601181bd7f23f20d70931d2b7080b353637ed9f698df5c27c1475409bf9709d55aa865544f9ee0031ec3ecdb30141a416df085c8f12db4cfa54cdfae327d545c419fa1c8ec60b1a72bce0f0e3b1047b8d074f9d17b8b3b96762eb5d4fe5f635fa2c6aa10bf78d964f98f7df29495f05041ed90f9b00d9cca6839c10c440c8eb11c39873aac0daa24c5cfb8c076b5de30d5ad2455875de26cc5209604ec2d0b13df40a24c20fc0627b5e10ac5013433e45336a7e11dfcac80afee90af192cbe23cde7dca569953052e1f5164e40eba488f4d40d3586d9fa3d543be682a11385f7e2a8ee08ed756cf39e0a9fef404bf7cf570b56bb6c958a4349233c05b3aa42b8333f21e46d863326aae7ad92cbc4a1aa4e36c39dfc7798431136978418e83a06688dc5172a492496f124b623c954b035d5428b695e8c4633fc6b3655abeb420696939d692b2c5fd98276e1d5061e4d8d19db1b37ffe2adaca9e5bb0b2840d15e87bbdcf54a4dd677e81ed4a2033d63b6e08cbd3d1a0ce4007c4c52ee280af5c4c8c055111b3c0c75c9aa5c8e017376b86870063bf49fd78a56231d19954f48b57dea5a1ebf2665e7f22089d0b1d39c8c17995a150a1d1a93e83c39ce62de2ad4ac75f363f3bccc8c24253d68a2be4967d6a0711ab0b10e36702b5752a09fb8580e5133d2d087c477d1a7323bc9dc45d8c0912732af90ebbaa82ee8e411a23f9c1e347ef63ea1a589239adcdd06754714be00928805833836e77c7d6bd9df9f0c967f63cfe6d92399d7a3ad87ae0fd4304764eb045cf9ccbc971415ca57e081fba55eb448244f73b4b4c7327f0dece56b32f571fee7ad439130005eec6d01cec882648d79bb05fd817ae3d0fdaf0c9d975432e166b288356901df1592f7eb2010048781af4fa1395199ec6be86076c345b0b999732bd617fdcddf34b1ded944575b937a6f930d227c16db2ec44dadd9366dfdc4e186c152a0450f74deabc39b53c800b335b0254cd6ccc5f856dc4dc90fd292ddc496d080b06e508d462fb517f98701881ab2887af025f01eebb433269e26915162d2f9d51846e8ef33db35928300a12319cc7fba74e731cddd5675e54a8e6e856f9b3cc932592dbb43d6bdab65dc985ad8516bac93c1fe9ca649e23a4739804b8ec4f640a042e5fb5bfe63e84b15790deeca30f1ca34479f1e1b5fd68f910713c51dd1025c04db0ffa5b948dfc9156a391b8f4f3ab060c34e56c33d3e59f829c1fef1985664f96b00eae72e502664673631a074234a37eb0bfcb1df56d996f048356debe2f2adaf741e0ddd1c3afcc0de60090b9ca36abcb6610036774638ee72d41e1836353639c0358ce39d1542335713e9bdb1c11ccbfbf82663e5afbdfcebeeeb078d5ca8b3a9e6840f8652443053ccbe82732bd2cedb6991b0905e0ff3b0d753b0dcfe3006cb39fe4c1a55fb919f4bcc7af35d9476532c3d6ce7c3fe077389d580ad8b857ca901bcaec575859a9314980fd2a31aca5aa976fa076219795f27e8cb7189c0f48930846fe8436252b8d6e6cba67260db257c9dfe750d8f14dc9d110d83a2b58283c25e47b8e13fd42f713123835b568e9452b0225987f73261c274083f1ba44ed3c6bb54d0611dd84e933f02f41eae588b546c8296df6281ea42aa5e787df07d4bcdea50a49cf8cb79d0d8b4dae5eadf43ee79d58ddb24517faa4056b2f32cd8d3409a4e01c27b8af0fc83071516c5da744cc5780c5b54c54fd13318776b92fcd9d7b92a93c36fb50778369554b4f361ec9a533f01ded29aa91b05c7b95b0d1df765c15f714a8cf3a0013fb8b0c7b5bc3555fb3f021431210eb9710f07ef2f4c0f1e877e66a98cf531dfb20e4f770f5f318e9d710831c1a2e6dca71438527584d68cbd68fab4fb5d2ea6cc33063253db3ff91425bab4a7975fd0bce5c34239971c62b6a28bc8beb7f899087f8921dfd289fcc029fa4ad7dfa99cdc5019cb2c951135679a76a65672574f24cb263af4d25211799b59e3e37509d1b3642d4a164010b4c6e74a9332022b40a4992b5f3f43d0b279131d4c06b862ccaaf613e0d28ff67573206e62ddad61c166ecf0f2cbff10132f35fb6166e855c01594206a1ab11e064411fcd55680d6fb558849d414873b0789478b39fe2534fe0984829e9d258d91f5aae26c8e3ccf8313139c066b6e9b4bf0926c7a731168394407ab1f9f1984a0c90f893b0cfba54781382d77566371195c2f853d7e84768d24fee0db362d40b682b82301f950c363b7d9d9c0475a9317ef6eb6c170a062ad92f34b6933f782c6bbca706dc78629055af60b15ebf7569a5e18876ecf6e23794dadc7aff6716dcad4a3085a0034afb025bd2d91e3a90d442d6a23ee371d1725a31f28bd20069924cee0fd3822538ba4cfc178e1e6116ec1378ce4b991d3ab16be80e19843804bfa734f4d7c90f8ca17ee23d79942cd3e6466302b85c72b918833b8906492f638f6d52d9f052449a51ebb4fc9d616e6fe25f28913636e5dc76901593b42844665c9c1e6ea10c34a845f22beb99b51f2b7ef1be13f998ea0279e7d4986af2ed4dbf1bb08cce500b6f92ee5567d5a92f3dabb5fff9ccfa4eb725a251961a83f2d234ac41ab84548aaebc380d76dcd2a2456ae7e79d5fd2575051391d3c5bb36619e6eab628b1f824df625becc83d3d9da1aefe3471dc09983c8f34b58cae73f1bdefeb3b90a91f41941d87bc2860c16fb8786050e12e0cf9294ce0c1227f6393f5d6de0c37ea285a30f9dfa47e5681bb139f69bc538056358d3cd86b3bef995e341db55fd3be8d5fa82b679075181cd0e5394319211975c19c16f00c9a88253c4533b9e9a4d34b4897f19da", 'hex')
      const prefix = Buffer.from("Filecoin Sign Bytes:\n");
      const txBlob = Buffer.concat([prefix, raw_bytes]);


      const pkResponse = await app.getAddressAndPubKey(PATH);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRawBytes(PATH, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_raw_bytes`)

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      // Verify signature
      const pk = Uint8Array.from(pkResponse.compressed_pk);
      const digest = getDigest(txBlob);
      const print = Buffer.from(digest)

      const signature = secp256k1.signatureImport(Uint8Array.from(resp.signature_der));
      const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
      expect(signatureOk).toEqual(true);
    } finally {
      await sim.close();
    }
  });
})



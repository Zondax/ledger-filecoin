const TransportNodeHid = require("@ledgerhq/hw-transport-node-hid").default;
const ledger_logs = require("@ledgerhq/logs");

const { FilecoinApp } = require("@zondax/ledger-filecoin");
import * as secp256k1 from "secp256k1";
import { getBlakeHash, getDigest } from "./tests/utils";
import {
  ETH_PATH,
  EXPECTED_ETH_PK,
  PATH,
  EIP191_FVM_PREFIX,
} from "./tests/common";
const sha3 = require("js-sha3");
import { ec } from "elliptic";

const msg_txn_string = Buffer.from("Hello World!", "utf8");
const msg_txn_hex = Buffer.from("\x00Hello World!", "utf8");

async function get_address(app: any) {
  const resp = await app.getAddressAndPubKey(PATH, true);

  console.log(resp);
}

function findRandom() {
  const num = (1 + parseInt(Math.random() * 100 + "")) % 256;

  return num;
}

function genRandomData(amount: number) {
  var buffer = Buffer.alloc(amount);
  for (var i = 0; i < amount; i++) {
    buffer[i] = findRandom();
  }
  return buffer;
}

async function sign_raw_bytes(app: any, amount: number) {
  const raw_bytes = genRandomData(amount);
  const prefix = Buffer.from("Filecoin Sign Bytes:\n");
  const txBlob = Buffer.concat([prefix, raw_bytes]);

  try {
    const signatureRequest = await app.signRawBytes(PATH, txBlob);
    console.log(JSON.stringify(signatureRequest));
  } catch (e) {
    console.log(e);
  }
}

async function sign(app: any) {
  const txBlob = Buffer.from(
    "8a0056040a60e1773636cf5e4a227d9ac24f20feca034ee25a5501f12b13543456cf32f3918bfdcfe636cd0cb5730d18ce401a01cd049d44000325f844000311821ae525aa1558465844a9059cbb000000000000000000000000ff000000000000000000000000000000001c048500000000000000000000000000000000000000000000000000005af3107a4000",
    "hex",
  );

  try {
    const pkResponse = await app.getAddressAndPubKey(PATH);
    console.log(pkResponse);

    const signatureRequest = app.sign(PATH, txBlob);

    const resp = await signatureRequest;
    console.log(resp);

    // Verify signature
    const pk = Uint8Array.from(pkResponse.compressed_pk);
    const digest = getDigest(txBlob);
    const signature = secp256k1.signatureImport(
      Uint8Array.from(resp.signature_der),
    );
    const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
    console.log("signature success: ", signatureOk);
  } catch (e) {
    console.log(e);
  }
}

async function sign_evm_eip191(app: any, msg_txn: Buffer) {
  try {
    const signatureRequest = app.signPersonalMessageEVM(
      ETH_PATH,
      msg_txn.toString("hex"),
    );

    const resp = await signatureRequest;
    console.log(resp);

    const header = Buffer.from("\x19Ethereum Signed Message:\n", "utf8");
    const msgLengthString = String(msg_txn.length);
    const msg = Buffer.concat([
      header,
      Buffer.from(msgLengthString, "utf8"),
      msg_txn,
    ]);
    const msgHash = sha3.keccak256(msg);
    const signature_obj = {
      r: Buffer.from(resp.r, "hex"),
      s: Buffer.from(resp.s, "hex"),
    };
    // Verify signature
    const EC = new ec("secp256k1");
    const signatureOK = EC.verify(
      msgHash,
      signature_obj,
      Buffer.from(EXPECTED_ETH_PK, "hex"),
      "hex",
    );
    console.log("signature success: ", signatureOK);
  } catch (e) {
    console.log(e);
  }
}

async function sign_fvm_eip191(app: any, msg_txn: Buffer) {
  try {
    const pkResponse = await app.getAddressAndPubKey(PATH);
    console.log(pkResponse);

    const signatureRequest = app.signPersonalMessageFVM(
      PATH,
      msg_txn,
    );

    const resp = await signatureRequest;
    console.log(resp);

    // Construct EIP-191 message format: "\x19Filecoin Signed Message:\n" + len + message
    const messageLengthBuffer = Buffer.alloc(4);
    messageLengthBuffer.writeUInt32BE(msg_txn.length, 0);

    const eip191Message = Buffer.concat([
      EIP191_FVM_PREFIX,
      messageLengthBuffer,
      msg_txn,
    ]);
    const messageHash = getBlakeHash(eip191Message);

    // Verify signature
    const publicKey = Uint8Array.from(pkResponse.compressed_pk);
    const signature = secp256k1.signatureImport(
      Uint8Array.from(resp.signature_der),
    );

    const isSignatureValid = secp256k1.ecdsaVerify(
      signature,
      Uint8Array.from(messageHash),
      publicKey,
    );

    console.log("signature success: ", isSignatureValid);
  } catch (e) {
    console.log(e);
  }
}

async function main() {
  const transport = await TransportNodeHid.open();
  ledger_logs.listen((log: any) => {
    console.log(`${log.type} ${log.message}`);
  });
  // const app = new AvalancheApp.default(transport);
  const app = new FilecoinApp(transport);

  await get_address(app);
  
  // sign 2MiB of random data
  await sign_raw_bytes(app, 1 * 1024);

  await sign_evm_eip191(app, msg_txn_hex);
  await sign_evm_eip191(app, msg_txn_string);

  await sign_fvm_eip191(app, msg_txn_hex);
  await sign_fvm_eip191(app, msg_txn_string);
  
  await sign(app);
}

(async () => {
  await main();
})();

import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import ledger_logs from '@ledgerhq/logs'

import FilecoinApp from "@zondax/ledger-filecoin";

export const PATH = "m/44'/461'/0'/0/1";


async function get_address(app) {
  const resp = await app.getAddressAndPubKey(PATH, true)

  console.log(resp)
}

function findRandom() {
  let num =
    (1 + parseInt((Math.random() * 100))) % 256;

  return num;
}

function genRandomData(amount) {
  var buffer = Buffer.alloc(amount);
  for (var i = 0; i < amount; i++) {
    buffer[i] = findRandom();
  }
  return buffer;
}

async function sign_raw_bytes(app, amount) {
  const raw_bytes = genRandomData(amount);
  const prefix = Buffer.from("Filecoin Sign Bytes:\n");
  const txBlob = Buffer.concat([prefix, raw_bytes]);

  // do not wait here..
  const signatureRequest = await app.signRawBytes(PATH, txBlob);

  console.log(JSON.stringify(signatureRequest))

}

async function main() {
    const transport = await TransportNodeHid.default.open();
    ledger_logs.listen((log) => {
        console.log(`${log.type} ${log.message}`)
    });
    // const app = new AvalancheApp.default(transport);
    const app = new FilecoinApp.default(transport);

    // sign 2MiB of random data
    await sign_raw_bytes(app, 2048 * 1024)
}

; (async () => {
  await main()
})()

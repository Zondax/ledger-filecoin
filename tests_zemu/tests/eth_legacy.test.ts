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

import Zemu from '@zondax/zemu'
import { models, defaultOptions, ETH_PATH, EXPECTED_PUBLIC_KEY} from './common'
// @ts-ignore
import FilecoinApp from "@zondax/ledger-filecoin";
import { Transaction } from "@ethereumjs/tx";
import Common from '@ethereumjs/common'
import { rlp, bufArrToArr} from "ethereumjs-util";
import { ec } from 'elliptic'
const BN = require('bn.js');

type TestData = {
    name: string,
    op: Buffer,
    chainId: number | undefined
}
const SIGN_TEST_DATA = [
  {
    name: 'basic_transfer',
    op: {
        value: 'abcdef00',
        to: 'df073477da421520cf03af261b782282c304ad66',
    },
    chainId: 9867,
  },
  {
    name: 'legacy_contract_deploy',
    op: {
        value: 'abcdef00',
        data: '1a8451e600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    },
    chainId: 5,
  },
  {
    name: 'legacy_contract_call',
    op: {
        to: '62650ae5c5777d1660cc17fcd4f48f6a66b9a4c2',
        value: 'abcdef01',
        data: 'ee919d500000000000000000000000000000000000000000000000000000000000000001',
    },
    chainId: 689,
  },
  {
    name: 'basic_transfer_no_eip155',
    op: {
        value: 'a1bcd400',
        to: 'df073477da421520cf03af261b782282c304ad66',
    },
  },
  {
    name: 'contract_deploy_no_eip155',
    op: {
        value: '1',
        data: '1a8451e600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    },
  },
]

const rawUnsignedLegacyTransaction = (params: any, chainId: number | undefined) => {

    const txParams = {
        nonce: '0x00',
        gasPrice: '0x6d6e2edc00',
        gasLimit: '0x2dc6c0',
        to: params.to !== undefined? '0x' + params.to: undefined,
        value: '0x' + params.value,
        data: params.data !== undefined? '0x' + params.data: undefined,
    }

    const chain = Common.forCustomChain(1, { name: 'avalanche', networkId: 1, chainId })
    const options = chainId !== undefined? {common: chain}: undefined

    // legacy
    const tx = Transaction.fromTxData(txParams, options)

    let unsignedTx: Buffer[] | Buffer
    unsignedTx = tx.getMessageToSign(false)
    unsignedTx = Buffer.from(rlp.encode(bufArrToArr(unsignedTx)))

    return unsignedTx

};

// an alternative verification method for legacy transactions, taken from obsidian
// which uses the ethereumIS library
function check_legacy_signature(hexTx: string, signature: any, chainId: number | undefined) {
  const ethTx = Buffer.from(hexTx, 'hex');

  const chain = Common.forCustomChain(1, { name: 'avalanche', networkId: 1, chainId })
  const tx_options = chainId !== undefined? {common: chain}: undefined

  const txnBufsDecoded: any = rlp.decode(ethTx).slice(0,6);
  const txnBufsMap = [signature.v, signature.r, signature.s].map(a=>Buffer.from(((a.length%2==1)?'0'+a:a),'hex'));

  const txnBufs = txnBufsDecoded.concat(txnBufsMap);

  const ethTxObj = Transaction.fromValuesArray(txnBufs, tx_options);

  return ethTxObj.verifySignature()
}

describe.each(models)('ETH_Legacy', function (m) {
  test.concurrent.each(SIGN_TEST_DATA)('sign legacy:  $name', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new FilecoinApp(sim.getTransport());

      const testcase = `${m.prefix.toLowerCase()}-eth-sign-${data.name}`

      const currentScreen = sim.snapshot()
      const msg = rawUnsignedLegacyTransaction(data.op, data.chainId);
      console.log("tx: ", msg.toString('hex'))

      const respReq = app.signETHTransaction(ETH_PATH, msg.toString('hex'), null);
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-eth-${data.name}`)

      const resp = await respReq

      console.log(resp, m.name, data.name)

      expect(resp).toHaveProperty('s')
      expect(resp).toHaveProperty('r')
      expect(resp).toHaveProperty('v')

      //Verify signature
      const EC = new ec("secp256k1");
      const sha3 = require('js-sha3');
      const msgHash = sha3.keccak256(msg);

      const pubKey = Buffer.from(EXPECTED_PUBLIC_KEY, 'hex')
      const signature_obj = {
        r: Buffer.from(resp.r, 'hex'),
        s: Buffer.from(resp.s, 'hex'),
      }

      const signatureOK = EC.verify(msgHash, signature_obj, pubKey, 'hex')
      expect(signatureOK).toEqual(true)

      // alternative verification to be safe
      const test = await check_legacy_signature(msg.toString('hex'),resp, data.chainId)
      expect(test).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

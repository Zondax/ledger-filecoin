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
import Zemu from '@zondax/zemu'
// @ts-ignore
import FilecoinApp, { CHAIN_TYPE } from "@zondax/ledger-filecoin";
import { ETH_PATH, EXPECTED_ETH_ADDRESS, EXPECTED_ETH_PK, defaultOptions, models } from './common'
import { ec } from 'elliptic'
jest.setTimeout(90000)
const sha3 = require('js-sha3')
const SIGN_TEST_DATA = [
  {
    name: 'personal_sign_msg',
    message: Buffer.from('Hello World!', 'utf8'),
    blind: false,
  },
  {
    name: 'personal_sign_big_msg',
    message: Buffer.from('Just a big dummy message to be sign. To test if we are parsing the chunks in the right way. By: Zondax', 'utf8'),
    blind: false,
  },
  {
    name: 'personal_sign_non_printable_msg',
    message: Buffer.from('\x00Hello World!', 'utf8'),
    blind: true,
  },
]
describe.each(models)('EIP191', function (m) {
  test.concurrent.each(SIGN_TEST_DATA)('sign transaction:  $name', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new FilecoinApp(sim.getTransport())
      const msgData = data.message

      if (data.blind) {
        await sim.toggleBlindSigning()
      }
      // do not wait here..
      const signatureRequest = app.signPersonalMessage(ETH_PATH, msgData.toString('hex'), CHAIN_TYPE.EVM)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-eth-${data.name}`, true, 0, 1500, data.blind)
      let resp = await signatureRequest
      console.log(resp)
      const header = Buffer.from('\x19Ethereum Signed Message:\n', 'utf8')
      const msgLengthString = String(msgData.length)
      const msg = Buffer.concat([header, Buffer.from(msgLengthString, 'utf8'), msgData])
      const msgHash = sha3.keccak256(msg)
      const signature_obj = {
        r: Buffer.from(resp.r, 'hex'),
        s: Buffer.from(resp.s, 'hex'),
      }
      // Verify signature
      const EC = new ec('secp256k1')
      const signatureOK = EC.verify(msgHash, signature_obj, Buffer.from(EXPECTED_ETH_PK, 'hex'), 'hex')
      expect(signatureOK).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
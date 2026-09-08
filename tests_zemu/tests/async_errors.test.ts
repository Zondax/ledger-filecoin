/** ******************************************************************************
 *  (c) 2026 Zondax AG
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

import { defaultOptions, models } from "./common";

jest.setTimeout(180000);

const nanoX = models.find((model) => model.name === "nanox")!;

const CLA = 0x06;
const CLA_ETH = 0xe0;
const INS_GET_VERSION = 0x00;
const INS_SIGN_ETH = 0x04;
const INS_SIGN_PERSONAL_MESSAGE = 0x08;
const P1_INIT = 0x00;
const P1_LAST = 0x02;

const SW_OK = 0x9000;
const SW_APP_REVIEW_PENDING = 0x6986;
const SW_SDK_REPLY_PENDING = 0x6901;

const NATIVE_PATH = Buffer.from(
  "2c000080cd010080000000800000000001000000",
  "hex",
);
const ETH_PATH = Buffer.from(
  "058000002c8000003c800000008000000000000005",
  "hex",
);
const ETH_BLIND_TRANSACTION = Buffer.from(
  "02f782013a8402a8af41843b9aca00850d8c7b50e68303d090944a2962ac08962819a8a17661970e3c0db765565e8817addd0864728ae780c0",
  "hex",
);

function apdu(
  cla: number,
  ins: number,
  p1: number,
  p2: number,
  data = Buffer.alloc(0),
): string {
  return Buffer.concat([
    Buffer.from([cla, ins, p1, p2, data.length]),
    data,
  ]).toString("hex");
}

async function raw(port: number, data: string, timeoutMs = 45000) {
  const response = await fetch(`http://127.0.0.1:${port}/apdu`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const body = await response.json();
  return body.data as string;
}

function statusOf(response: string): number {
  return Number.parseInt(response.slice(-4), 16);
}

function expectPendingRepliesBlocked(statuses: number[]) {
  if (process.env.EXPECT_APP_REVIEW_LOCK === "1") {
    expect(statuses).toEqual(
      new Array(statuses.length).fill(SW_APP_REVIEW_PENDING),
    );
    return;
  }

  // SDK 26.6.1+ blocks before dispatch with 0x6901. Older SDKs reach the
  // app-level review lock and return 0x6986. Either layer must refuse input.
  for (const status of statuses) {
    expect([SW_APP_REVIEW_PENDING, SW_SDK_REPLY_PENDING]).toContain(status);
  }
}

async function competingStatuses(port: number) {
  const getVersion = apdu(CLA, INS_GET_VERSION, 0x00, 0x00);
  return [
    statusOf(await raw(port, getVersion)),
    statusOf(await raw(port, getVersion)),
  ];
}

describe("Asynchronous error review lock", () => {
  test("blocks APDUs until native and Ethereum error callbacks reply", async () => {
    const sim = new Zemu(nanoX.path);
    try {
      await sim.start({ ...defaultOptions, model: nanoX.name });
      const port = (sim as any).speculosApiPort;
      const getVersion = apdu(CLA, INS_GET_VERSION, 0x00, 0x00);
      const observedCompetingStatuses: number[] = [];

      expect(
        statusOf(
          await raw(
            port,
            apdu(CLA, INS_SIGN_PERSONAL_MESSAGE, P1_INIT, 0x00, NATIVE_PATH),
          ),
        ),
      ).toEqual(SW_OK);

      const nonPrintableMessage = Buffer.from("0000000100", "hex");
      const nativeError = raw(
        port,
        apdu(
          CLA,
          INS_SIGN_PERSONAL_MESSAGE,
          P1_LAST,
          0x00,
          nonPrintableMessage,
        ),
        90000,
      );
      await sim.waitForText(/Blind signing must be/i, 20000);
      observedCompetingStatuses.push(...(await competingStatuses(port)));
      await sim.clickBoth();
      await nativeError;
      expect(statusOf(await raw(port, getVersion))).toEqual(SW_OK);

      const ethError = raw(
        port,
        apdu(
          CLA_ETH,
          INS_SIGN_ETH,
          P1_INIT,
          0x00,
          Buffer.concat([ETH_PATH, ETH_BLIND_TRANSACTION]),
        ),
        90000,
      );
      await sim.waitForText(/Blind signing must be/i, 20000);
      observedCompetingStatuses.push(...(await competingStatuses(port)));
      await sim.clickBoth();
      await ethError;
      expect(statusOf(await raw(port, getVersion))).toEqual(SW_OK);

      expectPendingRepliesBlocked(observedCompetingStatuses);
    } finally {
      await sim.close();
    }
  });
});

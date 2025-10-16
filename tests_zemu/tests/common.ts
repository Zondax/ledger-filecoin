import { DEFAULT_START_OPTIONS, IDeviceModel } from "@zondax/zemu";

const Resolve = require("path").resolve;

export const APP_SEED =
  "equip will roof matter pink blind book anxiety banner elbow sun young";

export const PATH = "m/44'/461'/0'/0/1";
export const PATH_TESTNET = "m/44'/1'/0'/0/1";
export const ETH_PATH = "m/44'/60'/0'/0'/5";
export const EXPECTED_PUBLIC_KEY =
  "024f1dd50f180bfd546339e75410b127331469837fa618d950f7cfb8be351b0020";

export const EXPECTED_ETH_PK =
  "044f1dd50f180bfd546339e75410b127331469837fa618d950f7cfb8be351b002035e2b0343bcf8bba5874b9c6c9311de5911d471e896b1f17f10137842a2265b0";
export const EXPECTED_ETH_ADDRESS =
  "0xcadff9350e9548bc68cb1e44d744bd9a801d5a5b";

export const EIP191_FVM_PREFIX = Buffer.from("\x19Filecoin Signed Message:\n");

const APP_PATH_X = Resolve("../app/output/app_x.elf");
const APP_PATH_SP = Resolve("../app/output/app_s2.elf");
const APP_PATH_ST = Resolve("../app/output/app_stax.elf");
const APP_PATH_FL = Resolve("../app/output/app_flex.elf");
const APP_PATH_AP = Resolve("../app/output/app_apex_p.elf");

export const models: IDeviceModel[] = [
  { name: "nanox", prefix: "X", path: APP_PATH_X },
  { name: "nanosp", prefix: "SP", path: APP_PATH_SP },
  { name: "stax", prefix: "ST", path: APP_PATH_ST },
  { name: "flex", prefix: "FL", path: APP_PATH_FL },
  { name: "apex_p", prefix: "AP", path: APP_PATH_AP },
];

export const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
};

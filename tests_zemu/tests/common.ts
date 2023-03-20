import { DEFAULT_START_OPTIONS, IDeviceModel } from '@zondax/zemu'

const Resolve = require("path").resolve;

export const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"

export const PATH = "m/44'/461'/0'/0/1";
export const PATH_TESTNET = "m/44'/1'/0'/0/1";
export const ETH_PATH = "m/44'/60'/0'/0'/5"
export const EXPECTED_PUBLIC_KEY = '024f1dd50f180bfd546339e75410b127331469837fa618d950f7cfb8be351b0020';

const APP_PATH_S = Resolve('../app/output/app_s.elf')
const APP_PATH_X = Resolve('../app/output/app_x.elf')
const APP_PATH_SP = Resolve('../app/output/app_s2.elf')

export const models: IDeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
]

export const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}


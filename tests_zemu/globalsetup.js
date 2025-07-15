const Zemu = require("@zondax/zemu");

/**
 * Initializes the emulator environment by setting up exit handlers,
 * pulling the latest emulator image, and stopping any running emulator containers.
 */
module.exports = async () => {
  await Zemu.default.checkAndPullImage();
  await Zemu.default.stopAllEmuContainers();
};

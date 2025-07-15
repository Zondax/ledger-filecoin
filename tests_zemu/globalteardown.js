const Zemu = require("@zondax/zemu");

module.exports = async () => {
  await Zemu.default.stopAllEmuContainers();
}; 
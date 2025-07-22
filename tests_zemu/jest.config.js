module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  transformIgnorePatterns: ["^.+\\.js$"],
  reporters: ["default", ["summary", { summaryThreshold: 1 }]],
  globalSetup: "./globalsetup.js",
  globalTeardown: "./globalteardown.js",
  testTimeout: 60000,
};

module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transformIgnorePatterns: ['^.+\\.js$'],
  globalSetup: "./jest/globalsetup.ts",
  globalTeardown: "./jest/globalteardown.ts",
  setupFilesAfterEnv: ["./jest/setup.ts"]
}



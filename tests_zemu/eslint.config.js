const typescriptParser = require("@typescript-eslint/parser");

const commonRules = {
  curly: "warn",
  "prefer-const": "warn",
  "no-else-return": "warn",
  complexity: ["warn", 1000],
  "no-unneeded-ternary": "warn",
  "no-alert": "warn",
  "no-empty": "warn",
  "no-useless-catch": "error",
  "require-await": "warn",
  "no-continue": "warn",
  "no-console": "off",
  "unused-imports/no-unused-imports": "warn",
  "no-unused-vars": "warn",
  "no-magic-numbers": "off",
};

module.exports = [
  {
    ignores: ["dist/*", "node_modules/*"],
  },
  {
    files: ["**/*.ts", "**/*.tsx"],
    languageOptions: {
      parser: typescriptParser,
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        window: "readonly",
        document: "readonly",
        process: "readonly",
        require: "readonly",
        jest: "readonly",
        expect: "readonly",
        describe: "readonly",
        test: "readonly",
        it: "readonly",
        beforeEach: "readonly",
        afterEach: "readonly",
        beforeAll: "readonly",
        afterAll: "readonly",
      },
      parserOptions: {
        project: "./tsconfig.json",
      },
    },
    plugins: {
      "unused-imports": require("eslint-plugin-unused-imports"),
      "@typescript-eslint": require("@typescript-eslint/eslint-plugin"),
      "eslint-plugin-tsdoc": require("eslint-plugin-tsdoc"),
    },
    rules: commonRules,
  },
  {
    files: ["**/*.js", "**/*.mjs"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        window: "readonly",
        document: "readonly",
        process: "readonly",
        require: "readonly",
      },
    },
    plugins: {
      "unused-imports": require("eslint-plugin-unused-imports"),
    },
    rules: commonRules,
  },
];

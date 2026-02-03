module.exports = {
  env: {
    es2020: true,
    node: true,
    browser: true
  },
  parser: '@typescript-eslint/parser',
  parserOptions: {
    sourceType: 'module',
    ecmaVersion: 2020
  },
  plugins: ['@typescript-eslint', 'import'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:import/recommended',
    'plugin:import/typescript',
    'prettier'
  ],
  rules: {
    'import/order': ['warn', { 'newlines-between': 'always' }],
    '@typescript-eslint/explicit-module-boundary-types': 'off'
  }
};

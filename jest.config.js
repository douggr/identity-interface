/**
 * https://dl2.dev - DL2 IT Services
 * Owlsome solutions. Owltstanding results.
 */

module.exports = {
  moduleFileExtensions: ['js', 'json', 'jsx', 'ts', 'tsx'],
  testEnvironment: 'node',
  testMatch: ['**/src/**/*.(spec|test).ts'],
  transform: {
    '\\.(ts|tsx)': 'ts-jest',
  },
  verbose: true,
};

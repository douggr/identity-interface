/**
 * https://dl2.dev - DL2 IT Services
 * Owlsome solutions. Owltstanding results.
 */

const { emptyDir, ensureDir, writeJson } = require('fs-extra');
const { inc } = require('semver');
const { resolve } = require('path');
const packages = require('../package.json');

const outputDir = resolve(__dirname, '../build');
const sourceDir = resolve(__dirname, '..');

const next = process.env.NEXT
  ? inc(packages.version, process.env.NEXT.toLowerCase())
  : packages.version;

emptyDir(outputDir)
  .then(() => ensureDir(outputDir))

  /**
   * create package.json
   */
  .then(() => {
    const {
      authors,
      dependencies,
      description,
      engines,
      license,
      name,
      repository,
    } = packages;

    const j = {
      authors,
      dependencies,
      description,
      engines,
      license,
      name,
      repository,
      version: next,
    };

    return writeJson(`${outputDir}/package.json`, j, { spaces: 2 });
  })

  /**
   * bump `version` (if requested)
   */
  .then(() => {
    const j = Object.assign(packages, { version: next });

    return writeJson(`${sourceDir}/package.json`, j, { spaces: 2 });
  });

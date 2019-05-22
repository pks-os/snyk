#!/usr/bin/env node
import 'source-map-support/register';
import * as Debug from 'debug';

// assert supported node runtime version
import * as runtime from './runtime';
// require analytics as soon as possible to start measuring execution time
import * as analytics from '../lib/analytics';
import * as alerts from '../lib/alerts';
import * as sln from '../lib/sln';
import {args as argsLib} from './args';
import {copy} from './copy';
import spinner = require('../lib/spinner');
import errors = require('../lib/errors/legacy-errors');
import ansiEscapes = require('ansi-escapes');
import {isPathToPackageFile} from '../lib/detect';
import {updateCheck} from '../lib/updater';
import { MissingTargetFileError } from '../lib/errors/missing-targetfile-error';

const debug = Debug('snyk');
const EXIT_CODES = {
  VULNS_FOUND: 1,
  ERROR: 2,
};

async function runCommand(args) {
  const result = await args.method(...args.options._);
  const res = analytics({
    args: args.options._,
    command: args.command,
  });

  if (result && !args.options.quiet) {
    if (args.options.copy) {
      copy(result);
      console.log('Result copied to clipboard');
    } else {
      console.log(result);
    }
  }

  return res;
}

async function handleError(args, error) {
  spinner.clearAll();
  let command = 'bad-command';
  let exitCode = EXIT_CODES.ERROR;

  if (error.code === 'VULNS') {
    // this isn't a bad command, so we won't record it as such
    command = args.command;
    exitCode = EXIT_CODES.VULNS_FOUND;
  } else if (!error.stack) { // log errors that are not error objects
    analytics.add('error', JSON.stringify(error));
    analytics.add('command', args.command);
  } else {
    // remove vulnerabilities from the errors
    // to keep the logs small
    if (error.stack && error.stack.vulnerabilities) {
      delete error.vulnerabilities;
    }
    if (error.message && error.message.vulnerabilities) {
      delete error.message.vulnerabilities;
    }
    if (error.vulnerabilities) {
      delete error.vulnerabilities;
    }

    analytics.add('error-message', error.message);
    analytics.add('error', error.stack);
    analytics.add('error-code', error.code);
    analytics.add('command', args.command);
  }

  const res = analytics({
    args: args.options._,
    command,
  });

  if (args.options.debug) {
    debug(error.stack);
  } else {
    if (!args.options.quiet) {

      const result = errors.message(error);
      if (args.options.copy) {
        copy(result);
        console.log('Result copied to clipboard');
      } else {
        if (`${error.code}`.indexOf('AUTH_') === 0) {
          // remove the last few lines
          const erase = ansiEscapes.eraseLines(4);
          process.stdout.write(erase);
        }
        console.error(result);
      }
    }
  }
  return { res, exitCode };
}

function checkRuntime() {
  if (!runtime.isSupported(process.versions.node)) {
    console.error(`${process.versions.node} is an unsupported nodejs ` +
      `runtime! Supported runtime range is '${runtime.supportedRange}'`);
    console.error('Please upgrade your nodejs runtime version and try again.');
    process.exit(EXIT_CODES.ERROR);
  }
}

// Check if user specify package file name as part of path
// and throw error if so.
function checkPaths(args) {
  for (const path of args.options._) {
    if (typeof path === 'string' && isPathToPackageFile(path)) {
      throw MissingTargetFileError(path);
    }
  }
}

async function main() {
  updateCheck();
  checkRuntime();

  const args = argsLib(process.argv);
  let res;
  let failed = false;
  let exitCode = EXIT_CODES.ERROR;
  try {
    if (args.options.file && args.options.file.match(/\.sln$/)) {
      sln.updateArgs(args);
    }
    checkPaths(args);
    res = await runCommand(args);
  } catch (error) {
    failed = true;
    const response = await handleError(args, error);
    res = response.res;
    exitCode = response.exitCode;
  }

  if (!args.options.json) {
    debug(alerts.displayAlerts());
  }

  if (!process.env.TAP && failed) {
    debug('Exit code: ' + exitCode);
    process.exit(exitCode);
  }

  return res;
}

const cli = main().catch((e) => {
  console.error('Something unexpected went wrong: ', e.stack);
  console.error('Exit code: ' + EXIT_CODES.ERROR);
  process.exit(EXIT_CODES.ERROR);
});

if (module.parent) {
  module.exports = cli;
}

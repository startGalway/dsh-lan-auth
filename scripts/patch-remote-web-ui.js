#!/usr/bin/env node
/**
 * patch-remote-web-ui — disable the pairing fence in the built client bundle of
 * @linxin666/dsh-remote-web-ui, for deployments where an external password gate
 * already authenticates every device.
 *
 * The plugin forces any non-loopback page through a gated /remote channel and
 * shows a full-page "device not paired" notice until the device is paired. When
 * a password gate fronts the loopback GUI (see packages/lan-auth), every request
 * the harness sees is loopback and already authenticated, so the channel and the
 * notice are redundant.
 *
 * This edits the installed package in place (lib/client.js). A plugin update
 * overwrites it — re-run this script afterwards.
 *
 * Usage:
 *   node scripts/patch-remote-web-ui.js              # patch the default profile
 *   node scripts/patch-remote-web-ui.js --check      # exit 1 if not patched
 *   node scripts/patch-remote-web-ui.js --path <lib/client.js>
 *
 * Exit codes: 0 patched/already patched, 1 --check found it unpatched, 2 file
 * missing, 3 unsupported bundle shape.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const MARKER = 'LOCAL PATCH (dsh-lan-auth)';
const DEFAULT_PLUGIN = path.join(
  os.homedir(),
  '.dsh/profiles/web/node_modules/@linxin666/dsh-remote-web-ui/lib/client.js',
);

function parseArgs(argv) {
  const options = { check: false, file: process.env.DSH_REMOTE_WEB_UI_CLIENT || DEFAULT_PLUGIN };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--check') options.check = true;
    else if (arg === '--path') {
      options.file = argv[index + 1];
      index += 1;
    } else if (arg === '--help' || arg === '-h') {
      console.log('usage: patch-remote-web-ui.js [--check] [--path <lib/client.js>]');
      process.exit(0);
    } else {
      console.error(`unknown argument: ${arg}`);
      process.exit(2);
    }
  }
  return options;
}

function main() {
  const { check, file } = parseArgs(process.argv.slice(2));
  if (!Number.isFinite(1) || typeof file !== 'string') {
    console.error('missing --path value');
    process.exit(2);
  }
  if (!fs.existsSync(file)) {
    console.error(`not found: ${file}`);
    console.error('install the plugin first: dsh plugin --profile web add @linxin666/dsh-remote-web-ui');
    process.exit(2);
  }
  const source = fs.readFileSync(file, 'utf8');
  const patched = source.includes(MARKER);
  if (check) {
    console.log(patched ? 'patched' : 'unpatched');
    process.exit(patched ? 0 : 1);
  }
  if (patched) {
    console.log('already patched, nothing to do');
    return;
  }
  const pattern = /(\n[ \t]*function remoteChannelRequired\([^)]*\) \{)\n/u;
  if (!pattern.test(source)) {
    console.error('remoteChannelRequired() not found — the bundle shape changed, patch manually');
    process.exit(3);
  }
  const injected = source.replace(
    pattern,
    `$1\n\t\t\t// ${MARKER}: device authentication is handled by the password gate in\n\t\t\t// front of the loopback listener, so the pairing channel is redundant here.\n\t\t\treturn false;\n`,
  );
  fs.copyFileSync(file, `${file}.orig-${Date.now()}`);
  fs.writeFileSync(file, injected);
  console.log(`patched ${file}`);
  console.log('reload the Web GUI (the plugin bundle URL carries a content revision)');
}

main();

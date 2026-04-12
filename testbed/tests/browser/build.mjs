#!/usr/bin/env node
// Bundle NDNts (WsTransport + Endpoint + Packet) into a single browser IIFE.
// The output is served by serve.mjs and loaded by the Playwright fixture page.
//
// Run: node build.mjs
//
// Output: fixture-page/ndnts.bundle.js  (exposed as window.NDNts)

import { build } from 'esbuild';
import { mkdirSync } from 'fs';

mkdirSync('fixture-page', { recursive: true });

await build({
  entryPoints: ['src/ndnts-browser.ts'],
  bundle: true,
  format: 'iife',
  globalName: 'NDNts',
  outfile: 'fixture-page/ndnts.bundle.js',
  platform: 'browser',
  // Let esbuild resolve browser-specific entry points.
  conditions: ['browser', 'import', 'default'],
  // NDNts uses BigInt — keep it as-is.
  target: 'es2020',
  minify: false,
  logLevel: 'info',
});

console.log('NDNts browser bundle → fixture-page/ndnts.bundle.js');

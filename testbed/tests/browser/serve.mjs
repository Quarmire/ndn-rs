#!/usr/bin/env node
// Minimal static file server for fixture-page/.
// Playwright webServer config starts this before running tests.

import { createServer } from 'http';
import { readFileSync } from 'fs';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';

const DIR = join(fileURLToPath(new URL('.', import.meta.url)), 'fixture-page');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  // Phase 6: SharedWorker bootstrap pulls a wasm-bindgen output bundle.
  // Browsers refuse to instantiate `.wasm` via the streaming compiler
  // unless the MIME type is exactly `application/wasm`.
  '.wasm': 'application/wasm',
  '.json': 'application/json; charset=utf-8',
};

const server = createServer((req, res) => {
  // Phase 6 fixtures live under `/sw-pkg/` (wasm-pack output) alongside
  // the existing index.html — subdirectory paths must work.
  let path = req.url === '/' ? 'index.html' : req.url.replace(/^\//, '');
  const qIdx = path.indexOf('?');
  if (qIdx !== -1) path = path.slice(0, qIdx);
  try {
    const data = readFileSync(join(DIR, path));
    const mime = MIME[extname(path)] ?? 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
    console.log(`[serve] 200 ${path}`);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end(`Not found: ${path}`);
    console.log(`[serve] 404 ${path}`);
  }
});

const PORT = parseInt(process.env.PORT ?? '3001', 10);
server.listen(PORT, '127.0.0.1', () => {
  console.log(`Fixture server → http://127.0.0.1:${PORT}`);
});

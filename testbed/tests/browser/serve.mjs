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
};

const server = createServer((req, res) => {
  const file = req.url === '/' ? 'index.html' : req.url.replace(/^\//, '');
  try {
    const data = readFileSync(join(DIR, file));
    const mime = MIME[extname(file)] ?? 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end(`Not found: ${file}`);
  }
});

const PORT = parseInt(process.env.PORT ?? '3001', 10);
server.listen(PORT, '127.0.0.1', () => {
  console.log(`Fixture server → http://127.0.0.1:${PORT}`);
});

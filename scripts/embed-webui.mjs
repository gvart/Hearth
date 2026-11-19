// SPDX-License-Identifier: AGPL-3.0-only
//
// Copies the built web UI (web/dist) to where the hub embeds it
// (internal/hub/webui/dist), gzipping text assets on the way. Only the .gz
// copy of a text asset is embedded: the hub serves it as is to browsers that
// accept gzip, and unpacks it for the rare client that does not. That keeps
// the binary, and so the agent's resident file pages, smaller (issue #209).
//
// usage: node scripts/embed-webui.mjs <web dist> <embed dir>
import { copyFileSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, extname, join, relative } from 'node:path';
import { constants, gzipSync } from 'node:zlib';

const compressible = new Set(['.css', '.html', '.js', '.json', '.map', '.mjs', '.svg', '.txt', '.webmanifest']);

const [src, dst] = process.argv.slice(2);
if (!src || !dst) {
  console.error('usage: node scripts/embed-webui.mjs <web dist> <embed dir>');
  process.exit(2);
}

rmSync(dst, { recursive: true, force: true });
mkdirSync(dst, { recursive: true });

for (const entry of readdirSync(src, { recursive: true, withFileTypes: true })) {
  if (!entry.isFile()) continue;
  const from = join(entry.parentPath, entry.name);
  const to = join(dst, relative(src, from));
  mkdirSync(dirname(to), { recursive: true });
  if (compressible.has(extname(entry.name))) {
    writeFileSync(`${to}.gz`, gzipSync(readFileSync(from), { level: constants.Z_BEST_COMPRESSION }));
  } else {
    copyFileSync(from, to);
  }
}
writeFileSync(join(dst, '.gitkeep'), '');

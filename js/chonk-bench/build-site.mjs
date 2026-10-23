// node build-site.mjs <dir>                write the bench page out as a static site
// node build-site.mjs --publish [remote]   build it and force-push it as the gh-pages branch
//                                          (default remote: origin; BB_FLOWS, CRS_PATH as for serve.mjs)
//
// The same tree serve.mjs serves, as plain files: the listings serve.mjs computes per request are
// written once, the CRS prefix is cut from the full CRS files, and each package contributes the
// files it would publish. Any static host serves it. One that cannot send the cross-origin
// isolation headers (GitHub Pages) gets them from coi.js's service worker.
//
// gh-pages is one commit with no history, replaced on every publish, so that old wasm modules and
// flows do not pile up in the repository.
import { execFileSync } from 'node:child_process';
import { closeSync, copyFileSync, mkdirSync, mkdtempSync, openSync, readSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { CRS, CRS_FILES, FLOWS, HERE, PACKAGES, flows, modules, pin7 } from './site.mjs';

const run = (cmd, args, opts = {}) => execFileSync(cmd, args, { encoding: 'utf8', ...opts });

function copy(from, to) {
  mkdirSync(dirname(to), { recursive: true });
  copyFileSync(from, to);
}

/** The first `length` bytes of `path`. */
function prefix(path, length) {
  const buf = Buffer.alloc(length);
  const fd = openSync(path, 'r');
  try {
    if (readSync(fd, buf, 0, length, 0) !== length) throw new Error(`${path} is shorter than ${length} bytes`);
  } finally {
    closeSync(fd);
  }
  return buf;
}

function build(out) {
  for (const file of ['index.html', 'app.mjs', 'flow.mjs', 'coi.js']) copy(join(HERE, file), join(out, file));
  // No Jekyll: GitHub Pages would otherwise process the tree and drop files that start with '_'.
  writeFileSync(join(out, '.nojekyll'), '');

  for (const [name, dir] of Object.entries(PACKAGES)) {
    const root = realpathSync(dir);
    const [{ files }] = JSON.parse(run('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root }));
    for (const { path } of files) copy(join(root, path), join(out, 'pkg', name, path));
  }

  mkdirSync(join(out, 'api'), { recursive: true });
  const list = flows();
  writeFileSync(join(out, 'api/flows.json'), JSON.stringify(list));
  writeFileSync(join(out, 'api/modules.json'), JSON.stringify(modules()));
  for (const { name } of list) copy(join(FLOWS, name, 'ivc-inputs.msgpack'), join(out, 'flows', name));

  mkdirSync(join(out, 'crs'), { recursive: true });
  for (const [name, [file, length]] of Object.entries(CRS_FILES)) {
    writeFileSync(join(out, 'crs', name), prefix(join(CRS, file), length));
  }
  return list.length;
}

if (process.argv[2] === '--publish') {
  const remote = process.argv[3] ?? 'origin';
  const url = run('git', ['remote', 'get-url', remote], { cwd: HERE }).trim();
  const head = run('git', ['rev-parse', '--short', 'HEAD'], { cwd: HERE }).trim();
  const out = mkdtempSync(join(tmpdir(), 'chonk-bench-site-'));
  try {
    const n = build(out);
    const git = args => run('git', ['-c', 'commit.gpgsign=false', ...args], { cwd: out, stdio: 'inherit' });
    git(['init', '-q', '-b', 'gh-pages']);
    git(['add', '-A']);
    git(['commit', '-q', '-m', `chonk bench: bb-ref ${head}, pin ${pin7()}, ${n} flows`]);
    git(['push', '-q', '--force', url, 'gh-pages']);
    console.log(`published bb-ref ${head} (pin ${pin7()}) to ${url} gh-pages`);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
} else if (process.argv[2]) {
  const n = build(process.argv[2]);
  console.log(`wrote ${process.argv[2]}: ${n} flows, pin ${pin7()}`);
} else {
  console.error('usage: node build-site.mjs <dir> | --publish [remote]');
  process.exit(1);
}

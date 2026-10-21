// Node 22+ interactive reference client. Secrets are prompted without echo and
// never passed as command-line arguments. Login prints its session exactly once.
import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
import { enroll, login } from './client.mjs';

const [action, origin, name] = process.argv.slice(2);
if (!['enroll', 'login'].includes(action) || !origin || (action === 'login' && !name)) {
  throw new Error('Usage: node cli.mjs enroll <origin> | login <origin> <login>');
}
let hidden = false;
const output = new Writable({ write(chunk, _encoding, done) {
  if (!hidden) process.stdout.write(chunk);
  done();
}});
const terminal = createInterface({ input: process.stdin, output, terminal: process.stdin.isTTY });
const promptSecret = async (label) => {
  process.stdout.write(label);
  hidden = true;
  try { return await terminal.question(''); }
  finally { hidden = false; process.stdout.write('\n'); }
};
try {
  const capability = action === 'enroll' ? await promptSecret('Enrollment capability: ') : '';
  const password = await promptSecret('Password (kept in this client): ');
  if (action === 'enroll') {
    await enroll(origin, capability, password);
    process.stdout.write('Enrollment complete. Log in to establish a session.\n');
  } else {
    process.stdout.write(JSON.stringify(await login(origin, name, password)) + '\n');
  }
} finally { terminal.close(); }

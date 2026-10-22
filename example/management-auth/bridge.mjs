// Test-only process boundary for the real Web Crypto client. No npm packages.
import { createInterface } from 'node:readline';
import { deriveCredential, enroll, login } from './client.mjs';
for await (const line of createInterface({ input: process.stdin })) {
  try {
    const { operation, password, parameters, origin, capability, name } = JSON.parse(line);
    let value;
    switch (operation) {
      case 'derive': value = await deriveCredential(password, parameters); break;
      case 'enroll': await enroll(origin, capability, password); value = true; break;
      case 'login': value = await login(origin, name, password); break;
      default: throw new Error('unsupported operation');
    }
    process.stdout.write(JSON.stringify(value) + '\n');
  } catch {
    process.stdout.write('{"error":"client operation failed"}\n');
  }
}

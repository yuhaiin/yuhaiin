// Shared browser/Node Web Crypto reference for yuhaiin-react. Passwords and
// derived credentials are never placed in URLs or browser persistent storage.
export async function deriveCredential(password, parameters) {
  if (parameters.algorithm !== 'pbkdf2-sha256-v1' || parameters.iterations !== 600000 ||
      parameters.digest !== 'SHA-256' || parameters.bytes !== 32 ||
      parameters.normalization !== 'NFC' || parameters.encoding !== 'utf-8/base64url-unpadded') {
    throw new Error('Unsupported password KDF parameters');
  }
  for (const character of password) {
    const point = character.codePointAt(0);
    if (point >= 0xd800 && point <= 0xdfff) throw new Error('Invalid Unicode password');
  }
  const bytes = new TextEncoder().encode(password.normalize('NFC'));
  if (!bytes.length || bytes.length > 1024) throw new Error('Password must contain 1 to 1024 UTF-8 bytes');
  const salt = Uint8Array.from(atob(parameters.salt.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  if (salt.length !== 16) throw new Error('Invalid client salt');
  const key = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveBits']);
  const derived = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256',
    iterations: 600000, salt }, key, 256));
  return btoa(String.fromCharCode(...derived)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function call(base, path, body, authorization) {
  const origin = new URL(base);
  if (origin.protocol !== 'https:' &&
      !(origin.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname))) {
    throw new Error('Remote management requires HTTPS');
  }
  if (origin.username || origin.password || origin.search || origin.hash) {
    throw new Error('Use an origin without URL credentials');
  }
  const response = await fetch(new URL(path, origin), {
    method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store',
    headers: { 'Content-Type': 'application/json', ...(authorization ? { Authorization: authorization } : {}) },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`Management request failed: HTTP ${response.status}`);
  return response.json();
}

export async function enroll(base, capability, password) {
  const authorization = `Enrollment ${capability}`;
  const parameters = await call(base, '/api/v2/auth/enrollment/parameters', {}, authorization);
  const clientCredential = await deriveCredential(password, parameters);
  await call(base, '/api/v2/auth/enrollment', { clientCredential }, authorization);
}

export async function login(base, name, password) {
  const parameters = await call(base, '/api/v2/auth/parameters', { login: name });
  const clientCredential = await deriveCredential(password, parameters);
  return call(base, '/api/v2/auth/login', { login: name, clientCredential });
}

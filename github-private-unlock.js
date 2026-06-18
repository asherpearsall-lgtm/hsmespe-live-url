(function () {
  const USER_ID_PREFIX = 'hsmespe-user-v1:';
  const CACHE_KEY = 'hsm_github_private_bundle_v1';

  function b64ToBytes(value) {
    const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    const raw = atob(padded);
    const out = new Uint8Array(raw.length);
    for (let index = 0; index < raw.length; index += 1) out[index] = raw.charCodeAt(index);
    return out;
  }

  function bytesToText(value) {
    return new TextDecoder().decode(value);
  }

  async function sha256Hex(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  async function deriveKey(username, password, kdf) {
    const secret = `${String(username || '').trim().toLowerCase()}:${password}`;
    const baseKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      {name: 'PBKDF2'},
      false,
      ['deriveKey']
    );
    return await crypto.subtle.deriveKey(
      {name: 'PBKDF2', salt: b64ToBytes(kdf.salt), iterations: Number(kdf.iterations || 600000), hash: 'SHA-256'},
      baseKey,
      {name: 'AES-GCM', length: 256},
      false,
      ['decrypt']
    );
  }

  async function decryptEnvelope(envelope, key, aad) {
    const plaintext = await crypto.subtle.decrypt(
      {name: 'AES-GCM', iv: b64ToBytes(envelope.nonce), additionalData: new TextEncoder().encode(aad ?? envelope.aad ?? '')},
      key,
      b64ToBytes(envelope.ciphertext)
    );
    return JSON.parse(bytesToText(new Uint8Array(plaintext)));
  }

  async function importAesKey(b64) {
    return await crypto.subtle.importKey('raw', b64ToBytes(b64), {name: 'AES-GCM'}, false, ['decrypt']);
  }

  async function fetchJson(url) {
    const response = await fetch(url, {cache: 'no-store', mode: 'cors'});
    if (!response.ok) throw new Error(`${url} returned ${response.status}`);
    return await response.json();
  }

  async function unlockWithPassword({username, password, baseUrl = '.'}) {
    const cleanUsername = String(username || '').trim();
    if (!cleanUsername || !password) throw new Error('Username and app password are required.');
    const root = String(baseUrl || '.').replace(/\/+$/, '');
    const userHash = await sha256Hex(`${USER_ID_PREFIX}${cleanUsername.toLowerCase()}`);
    const manifest = await fetchJson(`${root}/private/user-manifest.json`);
    const record = (manifest.user_unlock_records || []).find((item) => item.user_id_hash === userHash);
    if (!record) throw new Error('No encrypted unlock package was found for this user.');
    if (record.revoked) throw new Error('This user package is revoked.');
    const unlockKey = await deriveKey(cleanUsername, password, record.kdf || {});
    const unlock = await decryptEnvelope(record.unlock_package, unlockKey, `hsmespe-user-unlock:${userHash}`);
    const contentKey = await importAesKey(unlock.content_key);
    const bundleEnvelope = await fetchJson(`${root}/${manifest.bundle_path || 'private/estimator-bundle.enc.json'}`);
    const privateBundle = await decryptEnvelope(bundleEnvelope, contentKey, 'hsmespe-private-estimator-bundle');
    localStorage.setItem(CACHE_KEY, JSON.stringify({
      cachedAt: new Date().toISOString(),
      usernameHash: userHash,
      permission: unlock.permission || 'estimator',
      isAdmin: Boolean(unlock.is_admin),
      appVersion: privateBundle.app_version || '',
      packageVersion: privateBundle.package_version || '',
      capabilities: privateBundle.capabilities || [],
      privateBundle
    }));
    return {
      permission: unlock.permission || 'estimator',
      isAdmin: Boolean(unlock.is_admin),
      appVersion: privateBundle.app_version || '',
      packageVersion: privateBundle.package_version || ''
    };
  }

  window.HSMESPE_GITHUB_UNLOCK = {unlockWithPassword};
}());
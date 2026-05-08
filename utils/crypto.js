const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const KEYS_DIR = path.join(__dirname, '..', 'keys');



function generateRSAKeyPair(userId) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  fs.writeFileSync(path.join(KEYS_DIR, `${userId}_public.pem`),  publicKey);
  fs.writeFileSync(path.join(KEYS_DIR, `${userId}_private.pem`), privateKey);
  return { publicKey, privateKey };
}

function getPublicKey(userId) {
  const p = path.join(KEYS_DIR, `${userId}_public.pem`);
  return fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : null;
}

function getPrivateKey(userId) {
  const p = path.join(KEYS_DIR, `${userId}_private.pem`);
  return fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : null;
}


function encryptFileAES(fileBuffer, customAesKey = null, customIv = null, originalName = '') {
  // ── Key ──────────────────────────────────────────────────────────────────
  let aesKey;
  if (customAesKey) {
    if (!/^[0-9a-fA-F]{64}$/.test(customAesKey))
      throw new Error('AES key must be exactly 64 hex characters (256-bit)');
    aesKey = Buffer.from(customAesKey, 'hex');
  } else {
    aesKey = crypto.randomBytes(32);
  }

  let iv;
  if (customIv) {
    if (!/^[0-9a-fA-F]{32}$/.test(customIv))
      throw new Error('IV must be exactly 32 hex characters (128-bit)');
    iv = Buffer.from(customIv, 'hex');
  } else {
    iv = crypto.randomBytes(16);
  }

  const hmac = crypto
    .createHmac('sha256', aesKey)
    .update(iv)           // ← IV is bound here
    .update(fileBuffer)
    .digest('hex');

  const safeName = (originalName || '').replace(/[\r\n]/g, '_');


  const header  = Buffer.from(`VAULTSHARE3:${safeName}:${hmac}\n`, 'utf8');
  const payload = Buffer.concat([header, fileBuffer]);

  const cipher    = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);

  return {
    encryptedData: encrypted,
    aesKey: aesKey.toString('hex'),
    iv:     iv.toString('hex')
  };
}


function decryptFileAES(encryptedBuffer, aesKeyHex, ivHex) {
  const aesKey = Buffer.from(aesKeyHex, 'hex');
  const iv     = Buffer.from(ivHex,     'hex');

  let decrypted;
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
  } catch {
    throw new Error('Decryption failed — wrong AES key or IV');
  }

  const newlineIdx = decrypted.indexOf(0x0a); // '\n'

  if (newlineIdx !== -1) {
    const headerStr = decrypted.slice(0, newlineIdx).toString('utf8');

    // ── VAULTSHARE3: IV-bound HMAC (current format) ───────────────────────
    if (headerStr.startsWith('VAULTSHARE3:')) {
      const rest      = headerStr.slice('VAULTSHARE3:'.length); // "<name>:<hmac>"
      const lastColon = rest.lastIndexOf(':');

      if (lastColon === -1)
        throw new Error('Decryption failed — corrupted file header');

      const originalName  = rest.slice(0, lastColon);
      const storedHmacHex = rest.slice(lastColon + 1);
      const data          = decrypted.slice(newlineIdx + 1);

      const expectedHmac = crypto
        .createHmac('sha256', aesKey)
        .update(iv)         // ← IV is bound here (matches encrypt side)
        .update(data)
        .digest('hex');

      if (storedHmacHex !== expectedHmac)
        throw new Error('Decryption failed — wrong AES key or IV (integrity check failed)');

      return { data, originalName: originalName || null };
    }


    if (headerStr.startsWith('VAULTSHARE2:')) {
      const rest      = headerStr.slice('VAULTSHARE2:'.length);
      const lastColon = rest.lastIndexOf(':');

      if (lastColon === -1)
        throw new Error('Decryption failed — corrupted file header');

      const originalName  = rest.slice(0, lastColon);
      const storedHmacHex = rest.slice(lastColon + 1);
      const data          = decrypted.slice(newlineIdx + 1);

      const expectedHmac = crypto
        .createHmac('sha256', aesKey)
        .update(data)
        .digest('hex');

      if (storedHmacHex !== expectedHmac)
        throw new Error('Decryption failed — wrong AES key or IV (integrity check failed)');

      return { data, originalName: originalName || null };
    }

    if (headerStr.startsWith('VAULTSHARE:')) {
      const originalName = headerStr.slice('VAULTSHARE:'.length);
      const data         = decrypted.slice(newlineIdx + 1);
      return { data, originalName: originalName || null };
    }
  }


  return { data: decrypted, originalName: null };
}



function encryptAESKeyWithRSA(aesKeyHex, publicKeyPem) {
  return crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(aesKeyHex, 'utf8')
  ).toString('base64');
}

function decryptAESKeyWithRSA(encryptedKeyBase64, privateKeyPem) {
  return crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(encryptedKeyBase64, 'base64')
  ).toString('utf8');
}


function hashFile(fileBuffer) {
  return crypto.createHash('sha256').update(fileBuffer).digest('hex');
}

module.exports = {
  generateRSAKeyPair,
  getPublicKey,
  getPrivateKey,
  encryptFileAES,
  decryptFileAES,
  encryptAESKeyWithRSA,
  decryptAESKeyWithRSA,
  hashFile
};
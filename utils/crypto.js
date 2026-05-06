const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const KEYS_DIR = path.join(__dirname, '..', 'keys');

// Generate RSA key pair for a user
function generateRSAKeyPair(userId) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  fs.writeFileSync(path.join(KEYS_DIR, `${userId}_public.pem`), publicKey);
  fs.writeFileSync(path.join(KEYS_DIR, `${userId}_private.pem`), privateKey);

  return { publicKey, privateKey };
}

// Load a user's public key
function getPublicKey(userId) {
  const keyPath = path.join(KEYS_DIR, `${userId}_public.pem`);
  if (!fs.existsSync(keyPath)) return null;
  return fs.readFileSync(keyPath, 'utf8');
}

// Load a user's private key
function getPrivateKey(userId) {
  const keyPath = path.join(KEYS_DIR, `${userId}_private.pem`);
  if (!fs.existsSync(keyPath)) return null;
  return fs.readFileSync(keyPath, 'utf8');
}

// Encrypt a file buffer using AES-256-CBC
// Returns: { encryptedData, aesKey, iv }
function encryptFileAES(fileBuffer) {
  const aesKey = crypto.randomBytes(32); // 256-bit key
  const iv = crypto.randomBytes(16);     // 128-bit IV

  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);

  return {
    encryptedData: encrypted,
    aesKey: aesKey.toString('hex'),
    iv: iv.toString('hex')
  };
}

// Decrypt a file buffer using AES-256-CBC
function decryptFileAES(encryptedBuffer, aesKeyHex, ivHex) {
  const aesKey = Buffer.from(aesKeyHex, 'hex');
  const iv = Buffer.from(ivHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}

// Encrypt AES key using RSA public key
function encryptAESKeyWithRSA(aesKeyHex, publicKeyPem) {
  const encryptedKey = crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    Buffer.from(aesKeyHex, 'utf8')
  );
  return encryptedKey.toString('base64');
}

// Decrypt AES key using RSA private key
function decryptAESKeyWithRSA(encryptedKeyBase64, privateKeyPem) {
  const decryptedKey = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    Buffer.from(encryptedKeyBase64, 'base64')
  );
  return decryptedKey.toString('utf8');
}

// Generate SHA-256 hash of file for integrity check
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

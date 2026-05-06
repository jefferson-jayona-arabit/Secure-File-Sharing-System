const express = require('express');
const router = express.Router();
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const auth = require('../middleware/auth');
const { pool } = require('../utils/mysqlDb');
const {
  encryptFileAES, decryptFileAES,
  encryptAESKeyWithRSA, decryptAESKeyWithRSA,
  getPublicKey, getPrivateKey, hashFile
} = require('../utils/crypto');

const UPLOADS_DIR = path.join(__dirname, '..', 'uploads');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

// POST /api/files/upload
router.post('/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file provided' });

    const userId = req.user.id;
    const publicKey = getPublicKey(userId);
    if (!publicKey) return res.status(500).json({ error: 'RSA key not found' });

    const fileBuffer = req.file.buffer;
    const originalHash = hashFile(fileBuffer);
    const { encryptedData, aesKey, iv } = encryptFileAES(fileBuffer);
    const encryptedAESKey = encryptAESKeyWithRSA(aesKey, publicKey);

    const fileId = uuidv4();
    fs.writeFileSync(path.join(UPLOADS_DIR, `${fileId}.enc`), encryptedData);

    const algorithm = 'AES-256-CBC + RSA-OAEP-SHA256';

    // Insert into MySQL files table
    await pool.query(
      `INSERT INTO files
        (id, owner_id, original_name, mime_type, size, encrypted_aes_key, iv, original_hash, encryption_algorithm)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [fileId, userId, req.file.originalname, req.file.mimetype,
       req.file.size, encryptedAESKey, iv, originalHash, algorithm]
    );

    res.json({
      success: true,
      file: { id: fileId, name: req.file.originalname, size: req.file.size, algorithm },
      log: [
        `✅ File received: ${req.file.originalname} (${req.file.size} bytes)`,
        `🔑 AES-256 key generated: ${aesKey.substring(0, 16)}...`,
        `🔒 File encrypted with AES-256-CBC (IV: ${iv.substring(0, 16)}...)`,
        `🛡️  AES key encrypted with RSA-OAEP-SHA256 (2048-bit)`,
        `💾 Encrypted file stored: ${fileId}.enc`,
        `🗄️  Metadata saved to MySQL (files table)`,
        `#️⃣  Integrity hash (SHA-256): ${originalHash.substring(0, 32)}...`
      ]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Upload failed: ' + err.message });
  }
});

// GET /api/files
router.get('/', auth, async (req, res) => {
  const [rows] = await pool.query(
    'SELECT id, original_name AS name, size, uploaded_at AS uploadedAt, encryption_algorithm AS algorithm FROM files WHERE owner_id = ? ORDER BY uploaded_at DESC',
    [req.user.id]
  );
  res.json({ files: rows });
});

// GET /api/files/:id/download
router.get('/:id/download', auth, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM files WHERE id = ?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'File not found' });
    const fileMeta = rows[0];
    if (fileMeta.owner_id !== req.user.id) return res.status(403).json({ error: 'Access denied' });

    const privateKey = getPrivateKey(req.user.id);
    if (!privateKey) return res.status(500).json({ error: 'Private key not found' });

    const encPath = path.join(UPLOADS_DIR, `${fileMeta.id}.enc`);
    if (!fs.existsSync(encPath)) return res.status(404).json({ error: 'Encrypted file missing' });

    const encryptedData = fs.readFileSync(encPath);
    const aesKey = decryptAESKeyWithRSA(fileMeta.encrypted_aes_key, privateKey);
    const decryptedBuffer = decryptFileAES(encryptedData, aesKey, fileMeta.iv);

    const downloadHash = hashFile(decryptedBuffer);
    const integrityOk = downloadHash === fileMeta.original_hash;

    res.setHeader('Content-Disposition', `attachment; filename="${fileMeta.original_name}"`);
    res.setHeader('Content-Type', fileMeta.mime_type);
    res.setHeader('X-Integrity-Check', integrityOk ? 'PASSED' : 'FAILED');
    res.send(decryptedBuffer);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Download failed: ' + err.message });
  }
});

// GET /api/files/:id/info
router.get('/:id/info', auth, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM files WHERE id = ?', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'File not found' });
  const f = rows[0];
  if (f.owner_id !== req.user.id) return res.status(403).json({ error: 'Access denied' });
  res.json({
    id: f.id,
    name: f.original_name,
    size: f.size,
    uploadedAt: f.uploaded_at,
    algorithm: f.encryption_algorithm,
    iv: f.iv.substring(0, 16) + '...',
    encryptedKeyPreview: f.encrypted_aes_key.substring(0, 32) + '...',
    integrityHash: f.original_hash
  });
});

// DELETE /api/files/:id
router.delete('/:id', auth, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM files WHERE id = ?', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'File not found' });
  if (rows[0].owner_id !== req.user.id) return res.status(403).json({ error: 'Access denied' });

  const encPath = path.join(UPLOADS_DIR, `${rows[0].id}.enc`);
  if (fs.existsSync(encPath)) fs.unlinkSync(encPath);

  await pool.query('DELETE FROM files WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// GET /api/files/:id/download-encrypted
router.get('/:id/download-encrypted', auth, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM files WHERE id = ?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'File not found' });
    const fileMeta = rows[0];
    if (fileMeta.owner_id !== req.user.id) return res.status(403).json({ error: 'Access denied' });

    const encPath = path.join(UPLOADS_DIR, `${fileMeta.id}.enc`);
    if (!fs.existsSync(encPath)) return res.status(404).json({ error: 'Encrypted file missing' });

    const encryptedData = fs.readFileSync(encPath);

    res.setHeader('Content-Disposition', `attachment; filename="${fileMeta.original_name}.enc"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Original-Name', fileMeta.original_name);
    res.setHeader('X-Algorithm', fileMeta.encryption_algorithm);
    res.setHeader('X-IV-Preview', fileMeta.iv.substring(0, 16) + '...');
    res.setHeader('X-Encrypted-Size', encryptedData.length);
    res.send(encryptedData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Encrypted download failed: ' + err.message });
  }
});

module.exports = router;

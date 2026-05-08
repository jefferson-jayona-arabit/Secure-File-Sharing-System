const express  = require('express');
const router   = express.Router();
const multer   = require('multer');
const fs       = require('fs');
const path     = require('path');
const { v4: uuidv4 } = require('uuid');
const auth     = require('../middleware/auth');
const { pool } = require('../utils/mysqlDb');
const {
  encryptFileAES, decryptFileAES,
  encryptAESKeyWithRSA, decryptAESKeyWithRSA,
  getPublicKey, getPrivateKey, hashFile
} = require('../utils/crypto');
const fileStore = require('../utils/fileStore');

const UPLOADS_DIR = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  console.log('📁 Created uploads directory:', UPLOADS_DIR);
}


function sanitiseFilename(name) {
  return (name || 'download')
    .replace(/[^\x20-\x7E]/g, '_')   // non-ASCII → underscore
    .replace(/[\\/"]/g, '_')          // backslash, quote, forward-slash → underscore
    .replace(/^\s+|\s+$/g, '')        // trim leading/trailing spaces
    || 'download';
}

async function getFileMeta(fileId, userId) {
  console.log('🔍 DEBUG getFileMeta:');
  console.log('  - fileId:', fileId, 'type:', typeof fileId);
  console.log('  - userId:', userId, 'type:', typeof userId);

  try {
    const [rows] = await pool.query('SELECT * FROM files WHERE id = ?', [fileId]);
    console.log('  - MySQL query returned:', rows.length, 'rows');
    if (rows.length > 0) {
      const f = rows[0];
      console.log('    ✓ Found in MySQL, owner match?', f.owner_id === userId);
      if (f.owner_id === userId) return f;
      console.log('    ✗ Owner mismatch, access denied');
      return null;
    }
  } catch (err) {
    console.warn('  ✗ MySQL query failed:', err.message);
  }

  // JSON fallback
  const jsonFile = fileStore.getFileById(fileId);
  if (jsonFile && jsonFile.ownerId === userId) {
    return {
      id:                   jsonFile.id,
      owner_id:             jsonFile.ownerId,
      original_name:        jsonFile.originalName,
      mime_type:            jsonFile.mimeType,
      size:                 jsonFile.size,
      encrypted_aes_key:    jsonFile.encryptedAESKey,
      iv:                   jsonFile.iv,
      original_hash:        jsonFile.originalHash,
      encryption_algorithm: jsonFile.encryptionAlgorithm,
      uploaded_at:          jsonFile.uploadedAt
    };
  }

  console.log('  ✗ File not found in either storage');
  return null;
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/files/upload
// ─────────────────────────────────────────────────────────────────────────────
router.post('/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file provided' });

    const userId    = req.user.id;
    const publicKey = getPublicKey(userId);
    if (!publicKey) return res.status(500).json({ error: 'RSA public key not found for user' });

    const customAesKey = req.body.customAesKey || null;
    const customIv     = req.body.customIv     || null;
    const fileBuffer   = req.file.buffer;
    const originalHash = hashFile(fileBuffer);

    let encryptResult;
    try {
      encryptResult = encryptFileAES(fileBuffer, customAesKey, customIv, req.file.originalname);
    } catch (validationErr) {
      return res.status(400).json({ error: validationErr.message });
    }

    const { encryptedData, aesKey, iv } = encryptResult;
    const encryptedAESKey = encryptAESKeyWithRSA(aesKey, publicKey);

    const fileId  = uuidv4();
    const encPath = path.join(UPLOADS_DIR, `${fileId}.enc`);
    fs.writeFileSync(encPath, encryptedData);
    console.log(`✅ Encrypted file saved: ${encPath}`);

    const algorithm = 'AES-256-CBC + RSA-OAEP-SHA256';
    const keySource = customAesKey ? 'user-provided' : 'auto-generated';

    await pool.query(
      `INSERT INTO files
        (id, owner_id, original_name, mime_type, size, encrypted_aes_key, iv, original_hash, encryption_algorithm)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [fileId, userId, req.file.originalname, req.file.mimetype, req.file.size,
       encryptedAESKey, iv, originalHash, algorithm]
    );

    res.json({
      success: true,
      file: { id: fileId, name: req.file.originalname, size: req.file.size, algorithm },
      keySource,
      log: [
        `✅ File received: ${req.file.originalname} (${req.file.size} bytes)`,
        `🔑 AES-256 key ${keySource}: ${aesKey.substring(0, 16)}...`,
        `🔒 File encrypted with AES-256-CBC + HMAC-SHA256 (IV: ${iv.substring(0, 16)}...)`,
        `🛡️  AES key encrypted with RSA-OAEP-SHA256 (2048-bit)`,
        `💾 Encrypted file stored: ${fileId}.enc`,
        `🗄️  Metadata saved to MySQL (files table)`,
        `#️⃣  Integrity hash (SHA-256): ${originalHash.substring(0, 32)}...`
      ]
    });

  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed: ' + err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/files/:id/keys  — RSA-unwrap and return AES key + IV
// ─────────────────────────────────────────────────────────────────────────────
router.get('/:id/keys', auth, async (req, res) => {
  try {
    const fileMeta = await getFileMeta(req.params.id, req.user.id);
    if (!fileMeta) return res.status(404).json({ error: 'File not found' });

    const privateKey = getPrivateKey(req.user.id);
    if (!privateKey) return res.status(500).json({ error: 'RSA private key not found for user' });

    let aesKey;
    try {
      aesKey = decryptAESKeyWithRSA(fileMeta.encrypted_aes_key, privateKey);
    } catch {
      return res.status(500).json({ error: 'Failed to unwrap AES key with RSA private key' });
    }

    res.json({ aesKey, iv: fileMeta.iv });
  } catch (err) {
    console.error('Keys endpoint error:', err);
    res.status(500).json({ error: 'Failed to retrieve keys' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/files  — list files for the logged-in user
// ─────────────────────────────────────────────────────────────────────────────
router.get('/', auth, async (req, res) => {
  try {
    console.log('\n═══════════════════════════════════════════════════════');
    console.log('🔍 LIST FILES ENDPOINT');
    console.log('═══════════════════════════════════════════════════════');
    console.log('User ID:', req.user.id);

    let files = [];
    try {
      const [rows] = await pool.query(
        `SELECT id, original_name AS name, size,
                uploaded_at AS uploadedAt, encryption_algorithm AS algorithm
         FROM files WHERE owner_id = ? ORDER BY uploaded_at DESC`,
        [req.user.id]
      );
      console.log('MySQL query returned', rows.length, 'files');
      if (rows.length > 0) console.log('First row:', rows[0]);
      files = rows;
    } catch (err) {
      console.warn('MySQL query failed:', err.message);
    }

    const jsonFiles     = fileStore.getFilesByOwner(req.user.id);
    const mysqlFileIds  = files.map(f => f.id);
    const missingInMySQL = jsonFiles.filter(f => !mysqlFileIds.includes(f.id));

    files = [
      ...files,
      ...missingInMySQL.map(f => ({
        id: f.id, name: f.originalName, size: f.size,
        uploadedAt: f.uploadedAt, algorithm: f.encryptionAlgorithm
      }))
    ];
    files.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));

    console.log('Final file list being sent to frontend:');
    files.forEach((f, i) =>
      console.log(`  [${i}] id: ${f.id}, name: ${f.name}, uploadedAt: ${f.uploadedAt}`)
    );
    console.log('═══════════════════════════════════════════════════════\n');

    res.json({ files });
  } catch (err) {
    console.error('List files error:', err);
    res.status(500).json({ error: 'Failed to list files' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/files/:id/info
// ─────────────────────────────────────────────────────────────────────────────
router.get('/:id/info', auth, async (req, res) => {
  try {
    console.log('\n═══════════════════════════════════════════════════════');
    console.log('🔍 INFO ENDPOINT — id:', req.params.id);

    const fileMeta = await getFileMeta(req.params.id, req.user.id);
    if (!fileMeta) return res.status(404).json({ error: 'File not found' });

    const encPath    = path.join(UPLOADS_DIR, `${fileMeta.id}.enc`);
    const fileOnDisk = fs.existsSync(encPath);

    let rawAesKey = null;
    try {
      const privateKey = getPrivateKey(req.user.id);
      if (privateKey) rawAesKey = decryptAESKeyWithRSA(fileMeta.encrypted_aes_key, privateKey);
    } catch (e) {
      console.warn('Could not unwrap AES key for info display:', e.message);
    }

    res.json({
      id:            fileMeta.id,
      name:          fileMeta.original_name,
      size:          fileMeta.size,
      uploadedAt:    fileMeta.uploaded_at,
      algorithm:     fileMeta.encryption_algorithm,
      iv:            fileMeta.iv,
      aesKey:        rawAesKey,
      integrityHash: fileMeta.original_hash,
      fileOnDisk
    });

    console.log('Response data — id:', fileMeta.id, 'name:', fileMeta.original_name);
    console.log('═══════════════════════════════════════════════════════\n');
  } catch (err) {
    console.error('Info error:', err);
    res.status(500).json({ error: 'Failed to get file info' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/files/:id/download-encrypted  ⚠ MUST come BEFORE /:id/download
// ─────────────────────────────────────────────────────────────────────────────
router.get('/:id/download-encrypted', auth, async (req, res) => {
  try {
    console.log('\n═══════════════════════════════════════════════════════');
    console.log('🔍 DOWNLOAD-ENCRYPTED — id:', req.params.id);

    const fileMeta = await getFileMeta(req.params.id, req.user.id);
    if (!fileMeta) return res.status(404).json({ error: 'File not found' });

    const encPath = path.join(UPLOADS_DIR, `${fileMeta.id}.enc`);
    if (!fs.existsSync(encPath))
      return res.status(404).json({ error: `Encrypted file missing on server (${fileMeta.id}.enc)` });

    const encryptedData  = fs.readFileSync(encPath);
    const safeFilename   = sanitiseFilename(fileMeta.original_name) + '.enc';

    console.log('✓ Serving encrypted file:', safeFilename);
    console.log('═══════════════════════════════════════════════════════\n');

    res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Original-Name', sanitiseFilename(fileMeta.original_name));
    res.send(encryptedData);

  } catch (err) {
    console.error('Encrypted download error:', err);
    res.status(500).json({ error: 'Encrypted download failed: ' + err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/files/:id/download  — decrypt and stream original file
// ─────────────────────────────────────────────────────────────────────────────
router.get('/:id/download', auth, async (req, res) => {
  try {
    console.log('\n═══════════════════════════════════════════════════════');
    console.log('🔍 DOWNLOAD (DECRYPT) — id:', req.params.id);
    console.log('Query params:', req.query);

    if (!req.params.id || req.params.id === 'undefined')
      return res.status(400).json({ error: 'File ID is required' });

    const fileMeta = await getFileMeta(req.params.id, req.user.id);
    if (!fileMeta) return res.status(404).json({ error: 'File not found' });

    const encPath = path.join(UPLOADS_DIR, `${fileMeta.id}.enc`);
    if (!fs.existsSync(encPath))
      return res.status(404).json({ error: `Encrypted file missing on server` });

    const encryptedData = fs.readFileSync(encPath);

    // ── Resolve AES key ───────────────────────────────────────────────────────
    const customAesKey = req.query.customAesKey || null;
    const customIv     = req.query.customIv     || null;

    let aesKey;
    if (customAesKey) {
      if (!/^[0-9a-fA-F]{64}$/.test(customAesKey))
        return res.status(400).json({ error: 'Invalid AES key — must be 64 hex characters' });
      aesKey = customAesKey;
      console.log('Using custom AES key');
    } else {
      const privateKey = getPrivateKey(req.user.id);
      if (!privateKey)
        return res.status(500).json({ error: 'RSA private key not found for user' });
      try {
        aesKey = decryptAESKeyWithRSA(fileMeta.encrypted_aes_key, privateKey);
        console.log('✓ AES key unwrapped with RSA private key');
      } catch {
        return res.status(500).json({ error: 'Failed to unwrap AES key with RSA private key' });
      }
    }

    // ── Resolve IV ────────────────────────────────────────────────────────────
    if (customIv && !/^[0-9a-fA-F]{32}$/.test(customIv))
      return res.status(400).json({ error: 'Invalid IV — must be 32 hex characters' });
    const ivToUse = customIv || fileMeta.iv;

    console.log('Using IV:', ivToUse.substring(0, 16) + '...');

    // ── Decrypt ───────────────────────────────────────────────────────────────
    // ✅ Any wrong key OR wrong IV will now throw — no silent fallback
    let decryptResult;
    try {
      decryptResult = decryptFileAES(encryptedData, aesKey, ivToUse);
    } catch (e) {
      console.error('❌ Decryption failed:', e.message);
      // Return 400 so the frontend shows the error toast
      return res.status(400).json({ error: 'Decryption failed — wrong AES key or IV' });
    }

    const { data: decryptedBuffer, originalName: embeddedName } = decryptResult;

    // ── Integrity check ───────────────────────────────────────────────────────
    const downloadHash = hashFile(decryptedBuffer);
    const integrityOk  = downloadHash === fileMeta.original_hash;
    console.log(`✓ Integrity check: ${integrityOk ? 'PASSED ✅' : 'FAILED ❌'}`);

    // ── Filename ──────────────────────────────────────────────────────────────
    const rawName    = embeddedName || fileMeta.original_name;
    const finalName  = sanitiseFilename(rawName);
    console.log('✓ Embedded name:', embeddedName || '(none)');
    console.log('✓ Serving as:', finalName);
    console.log('═══════════════════════════════════════════════════════\n');

    res.setHeader('Content-Disposition', `attachment; filename="${finalName}"`);
    res.setHeader('Content-Type', fileMeta.mime_type || 'application/octet-stream');
    res.setHeader('X-Integrity-Check', integrityOk ? 'PASSED' : 'FAILED');
    res.send(decryptedBuffer);

  } catch (err) {
    console.error('❌ Download error:', err);
    res.status(500).json({ error: 'Download failed: ' + err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /api/files/:id
// ─────────────────────────────────────────────────────────────────────────────
router.delete('/:id', auth, async (req, res) => {
  try {
    const fileMeta = await getFileMeta(req.params.id, req.user.id);
    if (!fileMeta) return res.status(404).json({ error: 'File not found' });

    const encPath = path.join(UPLOADS_DIR, `${fileMeta.id}.enc`);
    if (fs.existsSync(encPath)) {
      fs.unlinkSync(encPath);
      console.log('🗑 Deleted enc file:', encPath);
    } else {
      console.warn('⚠ enc file not found on disk during delete:', encPath);
    }

    try {
      await pool.query('DELETE FROM files WHERE id = ?', [req.params.id]);
      console.log('✅ Deleted from MySQL');
    } catch (err) {
      console.warn('⚠ Could not delete from MySQL:', err.message);
    }

    fileStore.deleteFileMeta(req.params.id);
    res.json({ success: true });

  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Delete failed: ' + err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/files/decrypt-upload  — upload .enc, decrypt, download
// ─────────────────────────────────────────────────────────────────────────────
router.post('/decrypt-upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file provided' });

    const customAesKey = req.body.customAesKey || null;
    const customIv     = req.body.customIv     || null;

    if (!customAesKey || !customIv)
      return res.status(400).json({ error: 'AES key and IV are required for decryption' });
    if (!/^[0-9a-fA-F]{64}$/.test(customAesKey))
      return res.status(400).json({ error: 'AES key must be exactly 64 hex characters' });
    if (!/^[0-9a-fA-F]{32}$/.test(customIv))
      return res.status(400).json({ error: 'IV must be exactly 32 hex characters' });

    const encryptedBuffer = req.file.buffer;

    // ✅ Wrong key OR wrong IV will now throw — no silent fallback
    let decryptResult;
    try {
      decryptResult = decryptFileAES(encryptedBuffer, customAesKey, customIv);
    } catch (e) {
      console.error('❌ Decrypt-upload failed:', e.message);
      return res.status(400).json({ error: 'Decryption failed — wrong AES key or IV' });
    }

    const { data: decryptedBuffer, originalName: embeddedName } = decryptResult;

    // ── Filename ──────────────────────────────────────────────────────────────
    let rawName = embeddedName;
    if (!rawName) {
      rawName = req.file.originalname;
      if (rawName.endsWith('.enc')) rawName = rawName.slice(0, -4);
    }
    const originalName = sanitiseFilename(rawName);

    console.log('✓ Decrypt-upload — serving as:', originalName,
      embeddedName ? '(from embedded header)' : '(from filename fallback)');

    const integrityHash = hashFile(decryptedBuffer);

    res.setHeader('Content-Disposition', `attachment; filename="${originalName}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Integrity-Hash', integrityHash);
    res.setHeader('X-Original-Name', originalName);
    res.send(decryptedBuffer);

  } catch (err) {
    console.error('Decrypt-upload error:', err);
    res.status(500).json({ error: 'Decryption failed: ' + err.message });
  }
});

module.exports = router;
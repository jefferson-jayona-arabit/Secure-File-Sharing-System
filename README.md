# 🔐 VaultShare — Secure File Sharing System
### ITPE3227 – Integrative Programming and Technologies 2
**Hybrid Encryption: AES-256-CBC + RSA-OAEP-2048**

---

## System Overview
VaultShare is a secure web-based file sharing system that implements hybrid encryption:
- **AES-256-CBC** for fast, efficient file encryption
- **RSA-2048 OAEP** for secure AES key exchange
- **SHA-256** for file integrity verification
- **bcrypt** for password hashing
- **JWT** for authentication

## Setup Instructions

### Prerequisites
- Node.js v16+ 
- npm

### Installation
```bash
git clone <repo-url>
cd secure-file-share
npm install
```

### Run
```bash
node server.js
# or
npm start
```

Open http://localhost:3000

---

## Project Structure
```
secure-file-share/
├── server.js              # Express server entry point
├── routes/
│   ├── auth.js            # Register / Login endpoints
│   └── files.js           # Upload / Download / Delete endpoints
├── middleware/
│   └── auth.js            # JWT verification middleware
├── utils/
│   ├── crypto.js          # AES + RSA hybrid encryption logic
│   ├── db.js              # User store (JSON-based)
│   └── fileStore.js       # File metadata store (JSON-based)
├── public/
│   └── index.html         # Full frontend SPA
├── uploads/               # Encrypted files stored here (.enc)
├── keys/                  # RSA key pairs per user
├── data/                  # JSON databases
└── .env                   # Config (JWT secret, port)
```

## Encryption Flow
1. User uploads file → Multer receives it in memory
2. Server generates random **AES-256** key + IV per file
3. File encrypted with **AES-256-CBC**
4. AES key encrypted with user's **RSA-2048 public key** (OAEP-SHA256)
5. Encrypted file saved to `/uploads/*.enc`
6. Encrypted AES key + IV + SHA-256 hash stored in metadata

## Decryption Flow
1. User requests download → JWT verified
2. Server fetches encrypted file + encrypted AES key
3. **RSA private key** decrypts the AES key
4. **AES key** decrypts the file
5. SHA-256 integrity check performed
6. Original file sent to user

## API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/register | Register + generate RSA key pair |
| POST | /api/auth/login | Login, receive JWT |
| POST | /api/files/upload | Upload + encrypt file |
| GET  | /api/files | List user's files |
| GET  | /api/files/:id/download | Decrypt + download |
| GET  | /api/files/:id/info | View encryption metadata |
| DELETE | /api/files/:id | Delete file |

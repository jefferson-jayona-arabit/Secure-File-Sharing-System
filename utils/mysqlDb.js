const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     process.env.DB_PORT     || 3308,
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASSWORD || '1234',
  database: process.env.DB_NAME     || 'secure_file_share',
  waitForConnections: true,
  connectionLimit: 10,
});

// Create tables if they don't exist yet
async function initDB() {
  const conn = await pool.getConnection();
  try {
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id          VARCHAR(36)  PRIMARY KEY,
        name        VARCHAR(100) NOT NULL,
        email       VARCHAR(150) NOT NULL UNIQUE,
        password    VARCHAR(255) NOT NULL,
        created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS files (
        id                  VARCHAR(36)  PRIMARY KEY,
        owner_id            VARCHAR(36)  NOT NULL,
        original_name       VARCHAR(255) NOT NULL,
        mime_type           VARCHAR(100),
        size                BIGINT,
        encrypted_aes_key   TEXT         NOT NULL,
        iv                  VARCHAR(64)  NOT NULL,
        original_hash       VARCHAR(64)  NOT NULL,
        encryption_algorithm VARCHAR(100),
        uploaded_at         DATETIME     DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    console.log('✅ MySQL tables ready (users, files)');
  } finally {
    conn.release();
  }
}

module.exports = { pool, initDB };

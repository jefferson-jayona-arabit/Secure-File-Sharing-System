const express = require('express');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Ensure directories exist
['uploads', 'keys'].forEach(dir => {
  if (!fs.existsSync(path.join(__dirname, dir)))
    fs.mkdirSync(path.join(__dirname, dir), { recursive: true });
});

// Connect MySQL and create tables
const { initDB } = require('./utils/mysqlDb');
initDB().catch(err => {
  console.error('❌ MySQL connection failed:', err.message);
  console.error('👉 Check your .env DB_HOST, DB_USER, DB_PASSWORD, DB_NAME');
  process.exit(1);
});

app.use('/api/auth', require('./routes/auth'));
app.use('/api/files', require('./routes/files'));

app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🔐 VaultShare running at http://localhost:${PORT}`);
  console.log(`🗄️  MySQL: ${process.env.DB_USER}@${process.env.DB_HOST}/${process.env.DB_NAME}\n`);
});

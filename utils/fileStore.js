const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'data', 'files.json');

function loadFiles() {
  if (!fs.existsSync(DB_PATH)) {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify([]));
  }
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}

function saveFiles(files) {
  fs.writeFileSync(DB_PATH, JSON.stringify(files, null, 2));
}

function getFilesByOwner(ownerId) {
  return loadFiles().filter(f => f.ownerId === ownerId);
}

function getFileById(id) {
  return loadFiles().find(f => f.id === id);
}

function saveFileMeta(meta) {
  const files = loadFiles();
  files.push(meta);
  saveFiles(files);
  return meta;
}

function deleteFileMeta(id) {
  const files = loadFiles().filter(f => f.id !== id);
  saveFiles(files);
}

module.exports = { getFilesByOwner, getFileById, saveFileMeta, deleteFileMeta };

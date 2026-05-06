const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'data', 'users.json');

function loadUsers() {
  if (!fs.existsSync(DB_PATH)) {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify([]));
  }
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}

function saveUsers(users) {
  fs.writeFileSync(DB_PATH, JSON.stringify(users, null, 2));
}

function findUserByEmail(email) {
  return loadUsers().find(u => u.email === email);
}

function findUserById(id) {
  return loadUsers().find(u => u.id === id);
}

function createUser(user) {
  const users = loadUsers();
  users.push(user);
  saveUsers(users);
  return user;
}

module.exports = { findUserByEmail, findUserById, createUser, loadUsers };

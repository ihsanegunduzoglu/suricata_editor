const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', '..', 'data');
const DB_PATH = path.join(DATA_DIR, 'db.json');

const DEFAULT_DB = {
  currentSid: 1000000,
  sidToRev: {},
};

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function load() {
  ensureDataDir();
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(DEFAULT_DB, null, 2));
    return { ...DEFAULT_DB };
  }
  try {
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    return { ...DEFAULT_DB, ...parsed };
  } catch {
    return { ...DEFAULT_DB };
  }
}


function save(db) {
  ensureDataDir();
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function getDb() {
  if (!global.__SURICATA_DB__) global.__SURICATA_DB__ = load();
  return global.__SURICATA_DB__;
}

function persist() {
  save(getDb());
}

function allocateNextSid() {
  const db = getDb();
  db.currentSid += 1;
  persist();
  return db.currentSid;
}

function getStoredRevForSid(sid) {
  const db = getDb();
  return db.sidToRev[String(sid)] || 0;
}

function setStoredRevForSid(sid, rev) {
  const db = getDb();
  db.sidToRev[String(sid)] = Number(rev);
  persist();
}

module.exports = {
  getDb,
  allocateNextSid,
  getStoredRevForSid,
  setStoredRevForSid,
};



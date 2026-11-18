const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// مكان التخزين الدايم: على Railway بيبقى مسار الـ Volume (/data)، ومحليًا فولدر data
const DATA_DIR = process.env.DATA_DIR || process.env.RAILWAY_VOLUME_MOUNT_PATH || path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012';
const IV_LENGTH = 16;

function encrypt(text) {
    if (!text) return text;
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return text;
    try {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (e) { return text; }
}

// بصمة ثابتة للرقم القومي عشان نمنع التكرار (التشفير العادي بيطلع قيمة مختلفة كل مرة)
function hashId(id) {
    return crypto.createHmac('sha256', ENCRYPTION_KEY).update(String(id).trim()).digest('hex');
}

const db = new sqlite3.Database(path.join(DATA_DIR, 'forum.db'), (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('✅ Connected to SQLite database at', DATA_DIR);
        const sql = "CREATE TABLE IF NOT EXISTS registrations (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "full_name TEXT NOT NULL," +
            "national_id TEXT NOT NULL," +
            "national_id_hash TEXT," +
            "phone TEXT NOT NULL," +
            "email TEXT," +
            "governorate TEXT," +
            "qualification TEXT," +
            "job TEXT," +
            "committee TEXT," +
            "position TEXT," +
            "photo_path TEXT," +
            "id_front_path TEXT," +
            "id_back_path TEXT," +
            "created_at DATETIME DEFAULT CURRENT_TIMESTAMP" +
            ")";
        db.serialize(() => {
            db.run(sql);
            // لو الجدول قديم ومفيهوش العمود ده هيتضاف (الخطأ بيتجاهل لو موجود)
            db.run("ALTER TABLE registrations ADD COLUMN national_id_hash TEXT", () => {});
            db.run("CREATE UNIQUE INDEX IF NOT EXISTS idx_national_id_hash ON registrations(national_id_hash)");
        });
    }
});

module.exports = { db, encrypt, decrypt, hashId, DATA_DIR, UPLOADS_DIR };

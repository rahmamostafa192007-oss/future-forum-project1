require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const ExcelJS = require('exceljs');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const archiver = require('archiver');
const path = require('path');
const { db, encrypt, decrypt, hashId, DATA_DIR, UPLOADS_DIR } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Railway بيشغّل السيرفر ورا proxy، ومن غير السطر ده كل الزوار بيبانوا بنفس الـ IP
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10kb' }));
// ملفات الموقع بس (index.html, style.css, logo.png). الصور المرفوعة مش هنا خالص.
app.use(express.static('public'));

// ===== رفع الصور: بتتحفظ في /data/uploads (خارج public) =====
const ALLOWED_EXT = /^\.(jpe?g|png)$/;
const ALLOWED_MIME = /^image\/(jpeg|png)$/;

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, crypto.randomBytes(16).toString('hex') + ext);
    }
});
const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5 ميجا
    fileFilter: (req, file, cb) => {
        const okExt = ALLOWED_EXT.test(path.extname(file.originalname).toLowerCase());
        const okMime = ALLOWED_MIME.test(file.mimetype);
        if (okExt && okMime) return cb(null, true);
        cb(new Error('يُسمح فقط بالصور (jpg, jpeg, png)'));
    }
});
const uploadFields = upload.fields([
    { name: 'photo', maxCount: 1 },
    { name: 'id_front', maxCount: 1 },
    { name: 'id_back', maxCount: 1 }
]);

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'تم تجاوز المحاولات' } });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 3, message: { error: 'تم تجاوز الحد الأقصى للتسجيل' } });

function sanitize(str) {
    if (!str) return str;
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}

function removeUploaded(files) {
    Object.values(files || {}).flat().forEach(f => fs.unlink(f.path, () => {}));
}

// ===== 1. API التسجيل =====
app.post('/api/register', registerLimiter, (req, res, next) => {
    uploadFields(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        next();
    });
}, (req, res) => {
    let { full_name, phone, email, governorate, qualification, job, committee } = req.body;

    if (!full_name || !phone || !governorate || !qualification || !job) {
        removeUploaded(req.files);
        return res.status(400).json({ error: 'كل البيانات المطلوبة يجب ملؤها' });
    }

    full_name = sanitize(full_name); phone = sanitize(phone); email = sanitize(email);
    governorate = sanitize(governorate); qualification = sanitize(qualification); job = sanitize(job);
    const committeesString = Array.isArray(committee) ? committee.map(sanitize).join(', ') : sanitize(committee);

    // مفيش رقم قومي في النسخة دي. منع التكرار بيتم برقم التليفون (بصمة ثابتة في نفس العمود)
    const phoneDigits = String(phone).replace(/\D/g, '').replace(/^2(?=01)/, '');
    if (!/^01[0125]\d{8}$/.test(phoneDigits)) {
        removeUploaded(req.files);
        return res.status(400).json({ error: 'رقم التليفون غير صحيح' });
    }
    const encryptedNationalId = '';
    const nationalIdHash = hashId('phone:' + phoneDigits);

    // بنخزن اسم الملف بس، والمسار الحقيقي جوه /data/uploads
    const fileName = (key) => (req.files && req.files[key]) ? req.files[key][0].filename : null;
    const photoPath = fileName('photo');
    const idFrontPath = fileName('id_front');
    const idBackPath = fileName('id_back');

    const sql = "INSERT INTO registrations (full_name, national_id, national_id_hash, phone, email, governorate, qualification, job, committee, photo_path, id_front_path, id_back_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    db.run(sql, [full_name, encryptedNationalId, nationalIdHash, phone, email, governorate, qualification, job, committeesString, photoPath, idFrontPath, idBackPath], function (err) {
        if (err) {
            removeUploaded(req.files);
            if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'رقم التليفون ده مسجل بالفعل' });
            return res.status(500).json({ error: 'حدث خطأ في قاعدة البيانات' });
        }
        res.status(201).json({ message: 'تم التسجيل بنجاح' });
    });
});

// ===== 2. عدد المسجلين =====
app.get('/api/count', (req, res) => {
    db.get('SELECT COUNT(*) as count FROM registrations', [], (err, row) => {
        if (err) return res.status(500).json({ error: 'حدث خطأ' });
        res.json({ count: row.count });
    });
});

// ===== 3. حماية الأدمن =====
const authenticateAdmin = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'غير مصرح' });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err || user.role !== 'admin') return res.status(403).json({ error: 'جلسة منتهية' });
        next();
    });
};

// ===== 4. تسجيل الدخول =====
// يفضل تحط ADMIN_USERNAME و ADMIN_PASSWORD في Variables على Railway
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'AdminForum';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Forum@2026';

function safeEqual(a, b) {
    const ha = crypto.createHash('sha256').update(String(a)).digest();
    const hb = crypto.createHash('sha256').update(String(b)).digest();
    return crypto.timingSafeEqual(ha, hb);
}

app.post('/api/admin/login', loginLimiter, (req, res) => {
    const { username, password } = req.body || {};
    if (username && password && safeEqual(username, ADMIN_USERNAME) && safeEqual(password, ADMIN_PASSWORD)) {
        const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        return res.json({ token });
    }
    res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
});

// ===== 5. الصور: للأدمن بس، برابط مؤقت (10 دقايق) =====
const FILE_NAME_RE = /^[a-f0-9]{32}\.(jpe?g|png)$/;

function signedUrl(fileName) {
    if (!fileName || !FILE_NAME_RE.test(fileName)) return null;
    const t = jwt.sign({ file: fileName }, process.env.JWT_SECRET, { expiresIn: '10m' });
    return `/api/admin/file/${fileName}?t=${t}`;
}

app.get('/api/admin/file/:name', (req, res) => {
    const name = req.params.name;
    if (!FILE_NAME_RE.test(name)) return res.status(400).end();
    jwt.verify(String(req.query.t || ''), process.env.JWT_SECRET, (err, payload) => {
        if (err || payload.file !== name) return res.status(403).json({ error: 'الرابط غير صالح أو منتهي' });
        const filePath = path.join(UPLOADS_DIR, name);
        if (!fs.existsSync(filePath)) return res.status(404).end();
        res.setHeader('Cache-Control', 'private, no-store');
        res.sendFile(filePath);
    });
});

// ===== 6. جلب البيانات =====
app.get('/api/admin/data', authenticateAdmin, (req, res) => {
    db.all('SELECT * FROM registrations ORDER BY created_at DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'حدث خطأ' });
        res.json(rows.map(r => ({
            ...r,
            national_id: decrypt(r.national_id),
            photo_path: signedUrl(r.photo_path),
            id_front_path: signedUrl(r.id_front_path),
            id_back_path: signedUrl(r.id_back_path)
        })));
    });
});

// ===== تحميل كل الصور ZIP: فولدر لكل مسجّل باسمه =====
function cleanName(str) {
    return String(str || '')
        .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#x27;/g, "'")
        .replace(/[\\/:*?"<>|\r\n\t]/g, '').trim().slice(0, 60) || 'بدون اسم';
}

app.get('/api/admin/images', authenticateAdmin, (req, res) => {
    db.all('SELECT id, full_name, photo_path, id_front_path, id_back_path FROM registrations ORDER BY id', [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'حدث خطأ' });
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', 'attachment; filename=registration-images.zip');
        const archive = archiver('zip', { store: true }); // الصور مضغوطة أصلًا
        archive.on('error', () => res.destroy());
        archive.pipe(res);
        const kinds = [['photo_path', 'صورة شخصية'], ['id_front_path', 'البطاقة وش'], ['id_back_path', 'البطاقة ظهر']];
        rows.forEach(r => {
            const name = cleanName(r.full_name);
            kinds.forEach(([col, label]) => {
                const f = r[col];
                if (!f || !FILE_NAME_RE.test(f)) return;
                const fp = path.join(UPLOADS_DIR, f);
                if (!fs.existsSync(fp)) return;
                archive.file(fp, { name: `${r.id} - ${name}/${name} - ${label}${path.extname(f)}` });
            });
        });
        archive.finalize();
    });
});

// ===== 7. تحميل الإكسل =====
app.get('/api/admin/export', authenticateAdmin, async (req, res) => {
    db.all('SELECT * FROM registrations ORDER BY created_at DESC', [], async (err, rows) => {
        if (err) return res.status(500).json({ error: 'حدث خطأ' });
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('المسجلين');
        worksheet.columns = [
            { header: 'م', key: 'id' }, { header: 'الاسم', key: 'full_name' },
            { header: 'التليفون', key: 'phone' }, { header: 'الإيميل', key: 'email' }, { header: 'المحافظة', key: 'governorate' },
            { header: 'المؤهل', key: 'qualification' }, { header: 'الوظيفة', key: 'job' }, { header: 'اللجان', key: 'committee' },
            { header: 'التاريخ', key: 'created_at' }
        ];
        rows.forEach(row => worksheet.addRow(row));
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=registrations.xlsx');
        await workbook.xlsx.write(res);
        res.end();
    });
});

app.listen(PORT, () => console.log(`🚀 السيرفر شغال على المنفذ ${PORT} | التخزين: ${DATA_DIR}`));

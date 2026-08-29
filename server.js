require("dotenv").config();

const express = require("express");
const path = require("path");
const helmet = require("helmet");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const multer = require("multer");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.warn("DATABASE_URL is not configured. Database features will not work.");
}

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
    })
  : null;

const PRIVATE_DIR = path.join(__dirname, "private_uploads");
fs.mkdirSync(PRIVATE_DIR, { recursive: true });

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

if (pool) {
  app.use(session({
    store: new pgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET || "CHANGE_THIS_SESSION_SECRET",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 8
    }
  }));
} else {
  app.use(session({
    secret: process.env.SESSION_SECRET || "development-only-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", maxAge: 1000 * 60 * 60 * 8 }
  }));
}

app.use(express.static(path.join(__dirname, "public")));

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, PRIVATE_DIR),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, crypto.randomUUID() + ext);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024, files: 2 },
  fileFilter: (_req, file, cb) => {
    const allowed = new Set(["image/jpeg", "image/png", "application/pdf"]);
    if (!allowed.has(file.mimetype)) return cb(new Error("Only JPG, PNG, or PDF files are allowed."));
    cb(null, true);
  }
});

const requireDb = (req, res, next) => {
  if (!pool) return res.status(503).json({ error: "Database is not configured yet." });
  next();
};

const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ error: "Login required." });
  next();
};

const requireRole = role => (req, res, next) => {
  if (!req.session.user || req.session.user.role !== role) {
    return res.status(403).json({ error: "Access denied." });
  }
  next();
};

function validatePhone(value) {
  const phone = String(value || "").trim();
  if (!phone || !/^[+0-9()\-\s]{7,30}$/.test(phone)) return null;
  return phone;
}

function safePrivateFile(filename) {
  if (!filename || typeof filename !== "string") return null;
  const base = path.basename(filename);
  const filePath = path.resolve(PRIVATE_DIR, base);
  const privateRoot = path.resolve(PRIVATE_DIR) + path.sep;
  return filePath.startsWith(privateRoot) ? filePath : null;
}

async function initDb() {
  if (!pool) return;

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL CHECK (role IN ('coach', 'admin')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS teams (
      id SERIAL PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      coach_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      contact_phone VARCHAR(30) NOT NULL,
      school_or_club VARCHAR(200),
      status VARCHAR(30) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS players (
      id SERIAL PRIMARY KEY,
      team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
      full_name VARCHAR(150) NOT NULL,
      date_of_birth DATE,
      school_id_number VARCHAR(100),
      photo_path TEXT,
      school_id_path TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS registrations (
      id SERIAL PRIMARY KEY,
      team_id INTEGER UNIQUE NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
      fee_amount INTEGER NOT NULL DEFAULT 1500,
      payment_reference VARCHAR(150),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // New fields. We keep the old columns for compatibility with existing data.
  await pool.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS phone_number VARCHAR(30)`);
  await pool.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS aadhaar_path TEXT`);

  // If an earlier version stored the player's phone in school_id_number,
  // copy it once into the new phone_number field where possible.
  await pool.query(`
    UPDATE players
    SET phone_number = school_id_number
    WHERE phone_number IS NULL
      AND school_id_number IS NOT NULL
      AND school_id_number ~ '^[+0-9()\-\s]{7,30}$'
  `);

  // If an earlier version stored Aadhaar uploads in school_id_path,
  // make them available through the new aadhaar_path field.
  await pool.query(`
    UPDATE players
    SET aadhaar_path = school_id_path
    WHERE aadhaar_path IS NULL AND school_id_path IS NOT NULL
  `);

  const adminUsername = process.env.ADMIN_USERNAME;
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (adminUsername && adminPassword) {
    const existing = await pool.query("SELECT id FROM users WHERE username=$1", [adminUsername]);
    if (!existing.rowCount) {
      const hash = await bcrypt.hash(adminPassword, 12);
      await pool.query(
        "INSERT INTO users (username,password_hash,role) VALUES ($1,$2,'admin')",
        [adminUsername, hash]
      );
      console.log("Initial admin account created.");
    }
  }
}

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", databaseConfigured: Boolean(pool) });
});

app.post("/api/register-coach", requireDb, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    if (!username || !password || password.length < 8) {
      return res.status(400).json({ error: "Username and password (minimum 8 characters) are required." });
    }
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      "INSERT INTO users(username,password_hash,role) VALUES($1,$2,'coach')",
      [username, hash]
    );
    res.status(201).json({ message: "Coach account created. You can now log in." });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "Username already exists." });
    console.error(err);
    res.status(500).json({ error: "Could not create account." });
  }
});

app.post("/api/login", requireDb, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const result = await pool.query(
      "SELECT id,username,password_hash,role FROM users WHERE username=$1",
      [username]
    );
    if (!result.rowCount) return res.status(401).json({ error: "Invalid username or password." });
    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid username or password." });
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.json({ user: req.session.user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed." });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ message: "Logged out." }));
});

app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post("/api/teams", requireDb, requireAuth, requireRole("coach"), async (req, res) => {
  const client = await pool.connect();
  try {
    const name = String(req.body.name || "").trim();
    const contactPhone = validatePhone(req.body.contactPhone);
    const schoolOrClub = String(req.body.schoolOrClub || "").trim();
    if (!name || !contactPhone) {
      return res.status(400).json({ error: "Team name and a valid contact phone are required." });
    }

    await client.query("BEGIN");
    const count = await client.query("SELECT COUNT(*)::int AS count FROM teams");
    if (count.rows[0].count >= 32) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Registration is closed. The first 32 teams have already been reached." });
    }

    const team = await client.query(
      `INSERT INTO teams(name,coach_user_id,contact_phone,school_or_club)
       VALUES($1,$2,$3,$4) RETURNING id,name,status`,
      [name, req.session.user.id, contactPhone, schoolOrClub || null]
    );
    await client.query(
      "INSERT INTO registrations(team_id,fee_amount) VALUES($1,1500)",
      [team.rows[0].id]
    );
    await client.query("COMMIT");
    res.status(201).json({ team: team.rows[0], fee: 1500 });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ error: "Could not create team." });
  } finally {
    client.release();
  }
});

app.get("/api/my-teams", requireDb, requireAuth, requireRole("coach"), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.id,t.name,t.contact_phone,t.school_or_club,t.status,t.created_at,
              r.fee_amount,r.payment_reference,COUNT(p.id)::int AS player_count
       FROM teams t
       LEFT JOIN registrations r ON r.team_id=t.id
       LEFT JOIN players p ON p.team_id=t.id
       WHERE t.coach_user_id=$1
       GROUP BY t.id,r.fee_amount,r.payment_reference
       ORDER BY t.created_at DESC`,
      [req.session.user.id]
    );
    res.json({ teams: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load teams." });
  }
});

// Player uploads: phone number is a normal text field; Aadhaar is upload-only.
app.post("/api/teams/:teamId/players",
  requireDb,
  requireAuth,
  requireRole("coach"),
  upload.fields([
    { name: "photo", maxCount: 1 },
    { name: "aadhaarCard", maxCount: 1 }
  ]),
  async (req, res) => {
    const savedFiles = [];
    try {
      const teamId = Number(req.params.teamId);
      if (!Number.isInteger(teamId) || teamId < 1) return res.status(400).json({ error: "Invalid team." });

      const team = await pool.query(
        "SELECT id FROM teams WHERE id=$1 AND coach_user_id=$2",
        [teamId, req.session.user.id]
      );
      if (!team.rowCount) return res.status(404).json({ error: "Team not found." });

      const fullName = String(req.body.fullName || "").trim();
      const phoneNumber = validatePhone(req.body.phoneNumber);
      const dateOfBirth = req.body.dateOfBirth || null;
      const photo = req.files?.photo?.[0];
      const aadhaarCard = req.files?.aadhaarCard?.[0];

      if (!fullName) return res.status(400).json({ error: "Player name is required." });
      if (!phoneNumber) return res.status(400).json({ error: "A valid player phone number is required." });
      if (!photo || !aadhaarCard) return res.status(400).json({ error: "Player photo and Aadhaar Card are required." });

      savedFiles.push(photo.path, aadhaarCard.path);

      const result = await pool.query(
        `INSERT INTO players
          (team_id,full_name,date_of_birth,phone_number,aadhaar_path,photo_path,school_id_number,school_id_path)
         VALUES($1,$2,$3,$4,$5,$6,NULL,NULL)
         RETURNING id,team_id,full_name,date_of_birth,phone_number,created_at`,
        [teamId, fullName, dateOfBirth, phoneNumber, aadhaarCard.filename, photo.filename]
      );

      res.status(201).json({ player: result.rows[0] });
    } catch (err) {
      for (const file of savedFiles) {
        try { if (file && fs.existsSync(file)) fs.unlinkSync(file); } catch (_) {}
      }
      if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") return res.status(400).json({ error: "Each file must be 5 MB or smaller." });
        return res.status(400).json({ error: "Invalid upload." });
      }
      if (err.message && /Only JPG, PNG, or PDF/.test(err.message)) return res.status(400).json({ error: err.message });
      console.error(err);
      res.status(500).json({ error: "Could not add player." });
    }
  }
);

// Coach can view players belonging only to their own team.
app.get("/api/my-teams/:teamId/players", requireDb, requireAuth, requireRole("coach"), async (req, res) => {
  try {
    const teamId = Number(req.params.teamId);
    if (!Number.isInteger(teamId) || teamId < 1) {
      return res.status(400).json({ error: "Invalid team." });
    }

    const team = await pool.query(
      "SELECT id FROM teams WHERE id=$1 AND coach_user_id=$2",
      [teamId, req.session.user.id]
    );

    if (!team.rowCount) return res.status(404).json({ error: "Team not found." });

    const result = await pool.query(
      `SELECT id,team_id,full_name,date_of_birth,phone_number,created_at,
              CASE WHEN photo_path IS NOT NULL THEN true ELSE false END AS has_photo,
              CASE WHEN aadhaar_path IS NOT NULL THEN true ELSE false END AS has_aadhaar
       FROM players
       WHERE team_id=$1
       ORDER BY created_at ASC`,
      [teamId]
    );

    res.json({ players: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load player details." });
  }
});

// Coach-only private player files. Ownership is checked before every file request.
app.get("/api/my-players/:playerId/file/:kind", requireDb, requireAuth, requireRole("coach"), async (req, res) => {
  try {
    const playerId = Number(req.params.playerId);
    if (!Number.isInteger(playerId) || playerId < 1) {
      return res.status(400).json({ error: "Invalid player." });
    }

    const field = req.params.kind === "photo" ? "photo_path" :
                  req.params.kind === "aadhaar" ? "aadhaar_path" : null;

    if (!field) return res.status(400).json({ error: "Invalid file type." });

    const result = await pool.query(
      `SELECT p.${field} AS filename
       FROM players p
       JOIN teams t ON t.id=p.team_id
       WHERE p.id=$1 AND t.coach_user_id=$2`,
      [playerId, req.session.user.id]
    );

    if (!result.rowCount) return res.status(404).json({ error: "Player not found." });

    const filePath = safePrivateFile(result.rows[0].filename);
    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: "File not found." });
    }

    res.setHeader("Cache-Control", "private, no-store, max-age=0");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.sendFile(filePath);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not open file." });
  }
});

// Admin team list. Includes no private file URLs; files are served only through authenticated routes.
app.get("/api/admin/teams", requireDb, requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.id,t.name,t.contact_phone,t.school_or_club,t.status,t.created_at,
              u.username AS coach_username,r.fee_amount,r.payment_reference,
              COUNT(p.id)::int AS player_count
       FROM teams t
       JOIN users u ON u.id=t.coach_user_id
       LEFT JOIN registrations r ON r.team_id=t.id
       LEFT JOIN players p ON p.team_id=t.id
       GROUP BY t.id,u.username,r.fee_amount,r.payment_reference
       ORDER BY t.created_at ASC`
    );
    res.json({ teams: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load admin teams." });
  }
});

// Admin can view the player details belonging to one team.
app.get("/api/admin/teams/:teamId/players", requireDb, requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const teamId = Number(req.params.teamId);
    if (!Number.isInteger(teamId) || teamId < 1) return res.status(400).json({ error: "Invalid team." });

    const result = await pool.query(
      `SELECT id,team_id,full_name,date_of_birth,phone_number,created_at,
              CASE WHEN photo_path IS NOT NULL THEN true ELSE false END AS has_photo,
              CASE WHEN aadhaar_path IS NOT NULL THEN true ELSE false END AS has_aadhaar
       FROM players
       WHERE team_id=$1
       ORDER BY created_at ASC`,
      [teamId]
    );
    res.json({ players: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load player details." });
  }
});

app.patch("/api/admin/teams/:teamId/status", requireDb, requireAuth, requireRole("admin"), async (req, res) => {
  const allowed = new Set(["pending", "approved", "rejected"]);
  if (!allowed.has(req.body.status)) return res.status(400).json({ error: "Invalid status." });
  try {
    const result = await pool.query(
      "UPDATE teams SET status=$1 WHERE id=$2 RETURNING id,name,status",
      [req.body.status, Number(req.params.teamId)]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Team not found." });
    res.json({ team: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not update status." });
  }
});

// Admin-only private document/photo route. Never put these files in /public.
app.get("/api/admin/players/:playerId/file/:kind", requireDb, requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const field = req.params.kind === "photo" ? "photo_path" :
                  req.params.kind === "aadhaar" ? "aadhaar_path" : null;
    if (!field) return res.status(400).json({ error: "Invalid file type." });

    const result = await pool.query(`SELECT ${field} AS filename FROM players WHERE id=$1`, [Number(req.params.playerId)]);
    if (!result.rowCount) return res.status(404).json({ error: "Player not found." });

    const filePath = safePrivateFile(result.rows[0].filename);
    if (!filePath || !fs.existsSync(filePath)) return res.status(404).json({ error: "File not found." });

    res.setHeader("Cache-Control", "private, no-store, max-age=0");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.sendFile(filePath);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not open file." });
  }
});

// Backward-compatible admin route for the previous school-id button.
app.get("/api/admin/players/:playerId/file/school-id", requireDb, requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT COALESCE(aadhaar_path,school_id_path) AS filename FROM players WHERE id=$1",
      [Number(req.params.playerId)]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Player not found." });
    const filePath = safePrivateFile(result.rows[0].filename);
    if (!filePath || !fs.existsSync(filePath)) return res.status(404).json({ error: "File not found." });
    res.setHeader("Cache-Control", "private, no-store, max-age=0");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.sendFile(filePath);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not open file." });
  }
});

initDb()
  .then(() => app.listen(PORT, () => console.log(`Server listening on port ${PORT}`)))
  .catch(err => {
    console.error("Database initialization failed:", err);
    app.listen(PORT, () => console.log(`Server listening on port ${PORT} without database initialization.`));
  });

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
  console.warn("DATABASE_URL is not configured. The site will start, but database features will not work.");
}

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: process.env.NODE_ENV === "production"
        ? { rejectUnauthorized: false }
        : false
    })
  : null;

// Uploaded player documents are kept OUTSIDE /public.
const PRIVATE_DIR = path.join(__dirname, "private_uploads");
fs.mkdirSync(PRIVATE_DIR, { recursive: true });

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

const sessionConfig = {
  secret: process.env.SESSION_SECRET || "CHANGE_THIS_SESSION_SECRET",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 8
  }
};

if (pool) {
  sessionConfig.store = new pgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  });
}

app.use(session(sessionConfig));
app.use(express.static(path.join(__dirname, "public")));

// Only image/PDF uploads are accepted. Files get random names so the
// original filename is never used as a path.
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, PRIVATE_DIR),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname || "").toLowerCase();
      cb(null, crypto.randomUUID() + ext);
    }
  }),
  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 2
  },
  fileFilter: (req, file, cb) => {
    const allowed = new Set([
      "image/jpeg",
      "image/png",
      "application/pdf"
    ]);

    if (!allowed.has(file.mimetype)) {
      return cb(new Error("Only JPG, PNG, and PDF files are allowed."));
    }
    cb(null, true);
  }
});

const requireDb = (req, res, next) => {
  if (!pool) {
    return res.status(503).json({ error: "Database is not configured yet." });
  }
  next();
};

const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Login required." });
  }
  next();
};

const requireRole = (role) => (req, res, next) => {
  if (!req.session.user || req.session.user.role !== role) {
    return res.status(403).json({ error: "Access denied." });
  }
  next();
};

function validId(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function maskAadhaar(value) {
  const digits = String(value || "").replace(/\D/g, "");
  if (digits.length !== 12) return "—";
  return `XXXX-XXXX-${digits.slice(-4)}`;
}

async function initDb() {
  if (!pool) return;

  // New installations use Aadhaar field names from the beginning.
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
      status VARCHAR(30) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS players (
      id SERIAL PRIMARY KEY,
      team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
      full_name VARCHAR(150) NOT NULL,
      date_of_birth DATE,
      aadhaar_number VARCHAR(12) NOT NULL,
      photo_path TEXT,
      aadhaar_card_path TEXT,
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

  // Migration for your existing Stage-3 database.
  // The old project used school_id_number/school_id_path. Rename them once
  // so existing player records remain available to the admin.
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='players' AND column_name='school_id_number'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='players' AND column_name='aadhaar_number'
      ) THEN
        ALTER TABLE players RENAME COLUMN school_id_number TO aadhaar_number;
      END IF;

      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='players' AND column_name='school_id_path'
      ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='players' AND column_name='aadhaar_card_path'
      ) THEN
        ALTER TABLE players RENAME COLUMN school_id_path TO aadhaar_card_path;
      END IF;
    END $$;
  `);

  // If a partially modified database already has the new number/path columns,
  // make sure they exist before the API starts serving admin requests.
  await pool.query(`
    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS aadhaar_number VARCHAR(12),
      ADD COLUMN IF NOT EXISTS aadhaar_card_path TEXT,
      ADD COLUMN IF NOT EXISTS photo_path TEXT,
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
  `);

  const adminUsername = process.env.ADMIN_USERNAME;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (adminUsername && adminPassword) {
    const existing = await pool.query(
      "SELECT id FROM users WHERE username=$1",
      [adminUsername]
    );

    if (existing.rowCount === 0) {
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
  res.json({
    status: "ok",
    databaseConfigured: Boolean(pool)
  });
});

app.post("/api/register-coach", requireDb, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password || password.length < 8) {
      return res.status(400).json({
        error: "Username and password (minimum 8 characters) are required."
      });
    }

    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      "INSERT INTO users (username,password_hash,role) VALUES ($1,$2,'coach')",
      [String(username).trim(), hash]
    );

    res.status(201).json({
      message: "Coach account created. You can now log in."
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username already exists." });
    }
    console.error(err);
    res.status(500).json({ error: "Could not create account." });
  }
});

app.post("/api/login", requireDb, async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      "SELECT id, username, password_hash, role FROM users WHERE username=$1",
      [String(username || "").trim()]
    );

    if (!result.rowCount) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    const user = result.rows[0];
    const ok = await bcrypt.compare(password || "", user.password_hash);

    if (!ok) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role
    };

    res.json({ user: req.session.user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed." });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "Logged out." });
  });
});

app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

// Coach creates a team. Maximum = 32 teams.
app.post("/api/teams", requireDb, requireAuth, requireRole("coach"), async (req, res) => {
  const client = await pool.connect();

  try {
    const { name, contactPhone, schoolOrClub } = req.body;

    if (!name || !contactPhone) {
      return res.status(400).json({
        error: "Team name and contact phone are required."
      });
    }

    await client.query("BEGIN");

    const count = await client.query(
      "SELECT COUNT(*)::int AS count FROM teams"
    );

    if (count.rows[0].count >= 32) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "Registration is closed. The first 32 teams have already been reached."
      });
    }

    const team = await client.query(
      `INSERT INTO teams
       (name,coach_user_id,contact_phone,school_or_club)
       VALUES ($1,$2,$3,$4)
       RETURNING id,name,status,created_at`,
      [
        String(name).trim(),
        req.session.user.id,
        String(contactPhone).trim(),
        String(schoolOrClub || "").trim() || null
      ]
    );

    await client.query(
      "INSERT INTO registrations (team_id, fee_amount) VALUES ($1,1500)",
      [team.rows[0].id]
    );

    await client.query("COMMIT");

    res.status(201).json({
      team: team.rows[0],
      fee: 1500
    });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch (_) {}
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
              r.fee_amount,r.payment_reference,
              COUNT(p.id)::int AS player_count
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

// Add a player. The new preferred multipart names are:
//   photo       = player photo
//   aadhaarCard = Aadhaar card image/PDF
//   aadhaarNumber = 12-digit Aadhaar number
//
// Old Stage-3 names are also accepted temporarily so the existing coach.html
// does not break until you update its labels/field names.
app.post(
  "/api/teams/:teamId/players",
  requireDb,
  requireAuth,
  requireRole("coach"),
  upload.fields([
    { name: "photo", maxCount: 1 },
    { name: "aadhaarCard", maxCount: 1 },
    { name: "schoolId", maxCount: 1 }
  ]),
  async (req, res) => {
    const savedFiles = [];

    try {
      const teamId = validId(req.params.teamId);
      if (!teamId) {
        return res.status(400).json({ error: "Invalid team ID." });
      }

      const team = await pool.query(
        "SELECT id FROM teams WHERE id=$1 AND coach_user_id=$2",
        [teamId, req.session.user.id]
      );

      if (!team.rowCount) {
        return res.status(404).json({ error: "Team not found." });
      }

      const photo = req.files?.photo?.[0];
      // New field first; old schoolId field is accepted as a compatibility alias.
      const aadhaarCard = req.files?.aadhaarCard?.[0] || req.files?.schoolId?.[0];

      if (photo) savedFiles.push(photo.filename);
      if (aadhaarCard) savedFiles.push(aadhaarCard.filename);

      if (!photo || !aadhaarCard) {
        return res.status(400).json({
          error: "Player photo and Aadhaar card are required."
        });
      }

      const fullName = String(req.body.fullName || "").trim();
      const dateOfBirth = req.body.dateOfBirth || null;

      // Accept the new field and the old field as a temporary compatibility alias.
      const rawAadhaar = String(
        req.body.aadhaarNumber || req.body.schoolIdNumber || ""
      ).replace(/\s|-/g, "");

      if (!fullName) {
        return res.status(400).json({ error: "Player name is required." });
      }

      if (!/^\d{12}$/.test(rawAadhaar)) {
        return res.status(400).json({
          error: "Aadhaar number must contain exactly 12 digits."
        });
      }

      const result = await pool.query(
        `INSERT INTO players
         (team_id,full_name,date_of_birth,aadhaar_number,photo_path,aadhaar_card_path)
         VALUES ($1,$2,$3,$4,$5,$6)
         RETURNING id,full_name,date_of_birth,aadhaar_number,created_at`,
        [
          teamId,
          fullName,
          dateOfBirth,
          rawAadhaar,
          photo.filename,
          aadhaarCard.filename
        ]
      );

      res.status(201).json({
        player: result.rows[0]
      });
    } catch (err) {
      // Do not leave orphaned uploads behind if the database insert fails.
      for (const filename of savedFiles) {
        try {
          fs.unlinkSync(path.join(PRIVATE_DIR, path.basename(filename)));
        } catch (_) {}
      }

      console.error(err);
      res.status(500).json({ error: "Could not add player." });
    }
  }
);

// Admin: team summary.
app.get("/api/admin/teams", requireDb, requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.id,t.name,t.contact_phone,t.school_or_club,t.status,t.created_at,
              u.username AS coach_username,
              r.fee_amount,r.payment_reference,
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
    res.status(500).json({ error: "Could not load admin team list." });
  }
});

// Admin: complete player information for one team.
// This endpoint is protected by both login and admin role.
app.get(
  "/api/admin/teams/:teamId/players",
  requireDb,
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const teamId = validId(req.params.teamId);
      if (!teamId) {
        return res.status(400).json({ error: "Invalid team ID." });
      }

      const team = await pool.query(
        `SELECT id,name,contact_phone,school_or_club,status,created_at
         FROM teams
         WHERE id=$1`,
        [teamId]
      );

      if (!team.rowCount) {
        return res.status(404).json({ error: "Team not found." });
      }

      const result = await pool.query(
        `SELECT id,full_name,date_of_birth,aadhaar_number,
                created_at,
                CASE
                  WHEN aadhaar_number ~ '^\\d{12}$'
                  THEN 'XXXX-XXXX-' || RIGHT(aadhaar_number,4)
                  ELSE NULL
                END AS aadhaar_number_masked
         FROM players
         WHERE team_id=$1
         ORDER BY created_at ASC,id ASC`,
        [teamId]
      );

      res.set("Cache-Control", "no-store");
      res.json({
        team: team.rows[0],
        players: result.rows
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Could not load player information." });
    }
  }
);

// Admin can approve/reject/pause a team.
app.patch(
  "/api/admin/teams/:teamId/status",
  requireDb,
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    const allowed = new Set(["pending", "approved", "rejected"]);
    const teamId = validId(req.params.teamId);

    if (!teamId) {
      return res.status(400).json({ error: "Invalid team ID." });
    }

    if (!allowed.has(req.body.status)) {
      return res.status(400).json({ error: "Invalid status." });
    }

    try {
      const result = await pool.query(
        "UPDATE teams SET status=$1 WHERE id=$2 RETURNING id,name,status",
        [req.body.status, teamId]
      );

      if (!result.rowCount) {
        return res.status(404).json({ error: "Team not found." });
      }

      res.json({ team: result.rows[0] });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Could not update team status." });
    }
  }
);

// Admin-only private file access.
// The files are never exposed through /public or a static URL.
app.get(
  "/api/admin/players/:playerId/file/:kind",
  requireDb,
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const playerId = validId(req.params.playerId);
      if (!playerId) {
        return res.status(400).json({ error: "Invalid player ID." });
      }

      const fieldMap = {
        photo: "photo_path",
        aadhaar: "aadhaar_card_path"
      };

      const field = fieldMap[req.params.kind];
      if (!field) {
        return res.status(400).json({ error: "Invalid file type." });
      }

      const result = await pool.query(
        `SELECT ${field} AS filename FROM players WHERE id=$1`,
        [playerId]
      );

      if (!result.rowCount) {
        return res.status(404).json({ error: "Player not found." });
      }

      const filename = result.rows[0].filename;
      if (!filename) {
        return res.status(404).json({ error: "File not found." });
      }

      // Stored names are generated by the server. basename() also prevents
      // a database value from becoming a path outside PRIVATE_DIR.
      const safeFilename = path.basename(filename);
      const filePath = path.resolve(PRIVATE_DIR, safeFilename);

      if (!filePath.startsWith(path.resolve(PRIVATE_DIR) + path.sep)) {
        return res.status(403).json({ error: "Invalid file path." });
      }

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "File not found." });
      }

      res.set("Cache-Control", "private, no-store, max-age=0");
      res.set("X-Content-Type-Options", "nosniff");
      res.sendFile(filePath);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Could not open private file." });
    }
  }
);

// Temporary compatibility route for the previous admin.html.
// It still works, but the new admin.html should use /file/aadhaar.
app.get(
  "/api/admin/players/:playerId/file/school-id",
  requireDb,
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const playerId = validId(req.params.playerId);
      if (!playerId) return res.status(400).json({ error: "Invalid player ID." });

      const result = await pool.query(
        "SELECT aadhaar_card_path AS filename FROM players WHERE id=$1",
        [playerId]
      );

      if (!result.rowCount || !result.rows[0].filename) {
        return res.status(404).json({ error: "File not found." });
      }

      const safeFilename = path.basename(result.rows[0].filename);
      const filePath = path.resolve(PRIVATE_DIR, safeFilename);

      if (!filePath.startsWith(path.resolve(PRIVATE_DIR) + path.sep)) {
        return res.status(403).json({ error: "Invalid file path." });
      }

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "File not found." });
      }

      res.set("Cache-Control", "private, no-store, max-age=0");
      res.set("X-Content-Type-Options", "nosniff");
      res.sendFile(filePath);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Could not open private file." });
    }
  }
);

// Multer/file validation errors should be returned as JSON rather than HTML.
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err) {
    console.error(err.message || err);
    return res.status(400).json({
      error: err.message || "Upload failed."
    });
  }
  next(err);
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Database initialization failed:", err);
    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT} without database initialization.`);
    });
  });

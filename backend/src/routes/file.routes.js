import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import os from "os";

import { verifyToken } from "../middleware/auth.middleware.js";
import pool from "../config/db.js";
import supabase from "../config/supabase.js";

import { encryptFile, decryptFile } from "../utils/crypto/fileCrypto.js";
import { logAuditEvent } from "../utils/auditLogger.js";
import { scanFileForMalware } from "../utils/malwareScanner.js";

const router = express.Router();

/* =====================================================
   MULTER CONFIG
===================================================== */

const upload = multer({
  dest: "temp/",
  limits: {
    fileSize: 1024 * 1024 * 1024
  }
});

/* =====================================================
   DIRECTORIES SETUP
===================================================== */

const TEMP_DIR = "temp";
const QUARANTINE_DIR = "quarantine";

[TEMP_DIR, QUARANTINE_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
});

/* =====================================================
   UPLOAD
===================================================== */

router.post("/upload", verifyToken, upload.single("file"), async (req, res) => {
  let tempPath = null;
  let encryptedTempPath = null;

  try {
    if (req.user.role === "admin")
      return res.status(403).json({ message: "Admins cannot upload files" });

    if (!req.file)
      return res.status(400).json({ message: "No file uploaded" });

    const { originalname, mimetype, size, path: uploadedTempPath } = req.file;

    tempPath = uploadedTempPath;

    const scanResult = await scanFileForMalware(tempPath);

    let malwareStatus = "SAFE";
    if (!scanResult.safe) malwareStatus = "MALICIOUS";
    else if (scanResult.skipped) malwareStatus = "QUARANTINED";

    /* ===== QUARANTINE ===== */

    if (malwareStatus !== "SAFE") {
      const quarantineName = `${Date.now()}-${originalname}`;
      const quarantinePath = path.join(QUARANTINE_DIR, quarantineName);

      fs.renameSync(tempPath, quarantinePath);

      await pool.query(
        `INSERT INTO secure_files
        (user_id, original_name, stored_name, mime_type, file_size, malware_status, malicious_count, file_hash)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          req.user.id,
          originalname,
          quarantineName,
          mimetype,
          Number(size),
          malwareStatus,
          scanResult.maliciousCount || 0,
          scanResult.hash || null
        ]
      );

      return res.status(400).json({
        message: "File quarantined",
        status: malwareStatus
      });
    }

    /* ===== SAFE FILE ===== */

    const storedName = `${Date.now()}-${originalname}`;
    encryptedTempPath = path.join(TEMP_DIR, storedName);

    await encryptFile(tempPath, encryptedTempPath);
    fs.unlinkSync(tempPath);

    const buffer = fs.readFileSync(encryptedTempPath);

    const { error } = await supabase.storage
      .from("vault")
      .upload(storedName, buffer, {
        contentType: "application/octet-stream"
      });

    if (error) throw error;

    fs.unlinkSync(encryptedTempPath);

    await pool.query(
      `INSERT INTO secure_files
      (user_id, original_name, stored_name, mime_type, file_size, malware_status, malicious_count, file_hash)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        req.user.id,
        originalname,
        storedName,
        mimetype,
        Number(size),
        "SAFE",
        0,
        scanResult.hash || null
      ]
    );

    res.json({ message: "File uploaded securely" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Upload failed" });
  }
});

/* =====================================================
   PREVIEW  ✅ FIXED
===================================================== */

router.get("/preview/:id", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM secure_files WHERE id=$1 AND user_id=$2`,
      [req.params.id, req.user.id]
    );

    if (!result.rows.length)
      return res.status(404).json({ message: "File not found" });

    const file = result.rows[0];

    if (file.malware_status !== "SAFE")
      return res.status(403).json({ message: "File blocked" });

    const { data, error } = await supabase.storage
      .from("vault")
      .download(file.stored_name);

    if (error) throw error;

    const encryptedTempPath = path.join(os.tmpdir(), file.stored_name);
    fs.writeFileSync(
      encryptedTempPath,
      Buffer.from(await data.arrayBuffer())
    );

    const decryptedTempPath = path.join(os.tmpdir(), file.original_name);
    await decryptFile(encryptedTempPath, decryptedTempPath);

    fs.unlinkSync(encryptedTempPath);

    res.sendFile(decryptedTempPath, () => {
      fs.unlinkSync(decryptedTempPath);
    });

  } catch (err) {
    console.error("Preview error:", err);
    res.status(500).json({ message: "Preview failed" });
  }
});

/* =====================================================
   DOWNLOAD
===================================================== */

router.get("/download/:id", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM secure_files WHERE id=$1 AND user_id=$2`,
      [req.params.id, req.user.id]
    );

    if (!result.rows.length)
      return res.status(404).json({ message: "File not found" });

    const file = result.rows[0];

    if (file.malware_status !== "SAFE")
      return res.status(403).json({ message: "File blocked" });

    const { data } = await supabase.storage
      .from("vault")
      .download(file.stored_name);

    const encryptedTempPath = path.join(os.tmpdir(), file.stored_name);
    fs.writeFileSync(
      encryptedTempPath,
      Buffer.from(await data.arrayBuffer())
    );

    const decryptedTempPath = path.join(os.tmpdir(), file.original_name);
    await decryptFile(encryptedTempPath, decryptedTempPath);

    fs.unlinkSync(encryptedTempPath);

    res.download(decryptedTempPath, file.original_name, () => {
      fs.unlinkSync(decryptedTempPath);
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Download failed" });
  }
});

/* =====================================================
   DELETE
===================================================== */

router.delete("/delete/:id", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT stored_name FROM secure_files WHERE id=$1 AND user_id=$2`,
      [req.params.id, req.user.id]
    );

    if (!result.rows.length)
      return res.status(404).json({ message: "File not found" });

    const storedName = result.rows[0].stored_name;

    await supabase.storage.from("vault").remove([storedName]);

    await pool.query("DELETE FROM secure_files WHERE id=$1", [
      req.params.id
    ]);

    res.json({ message: "File deleted securely" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Delete failed" });
  }
});

/* =====================================================
   MY FILES
===================================================== */

router.get("/my-files", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, original_name, mime_type, file_size, created_at, malware_status
       FROM secure_files
       WHERE user_id=$1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch files" });
  }
});

export default router;
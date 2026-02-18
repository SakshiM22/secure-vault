import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import os from "os";

import { verifyToken } from "../middleware/auth.middleware.js";
import pool from "../config/db.js";
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
    fileSize: 32 * 1024 * 1024
  }
});

/* =====================================================
   DIRECTORIES SETUP
===================================================== */

const VAULT_DIR = "vault";
const QUARANTINE_DIR = "quarantine";
const TEMP_DIR = "temp";

[VAULT_DIR, QUARANTINE_DIR, TEMP_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir);
  }
});

/* =====================================================
   UPLOAD FILE
   SHA256 + AI MALWARE SCAN + AES ENCRYPTION
===================================================== */

router.post(
  "/upload",
  verifyToken,
  upload.single("file"),
  async (req, res) => {

    let tempPath = null;

    try {

      /* =========================
         VALIDATION
      ========================= */

      if (req.user.role === "admin") {
        return res.status(403).json({
          message: "Admins cannot upload files"
        });
      }

      if (!req.file) {
        return res.status(400).json({
          message: "No file uploaded"
        });
      }

      const {
        originalname,
        mimetype,
        size,
        path: uploadedTempPath
      } = req.file;

      tempPath = uploadedTempPath;

      console.log("Starting malware scan...");

      /* =========================
         STEP 1: SCAN FILE
      ========================= */

      const scanResult =
        await scanFileForMalware(tempPath);

      console.log("Scan result:", scanResult);

      const malwareStatus =
        scanResult.skipped
          ? "SCAN_SKIPPED"
          : scanResult.safe
            ? "SAFE"
            : "MALICIOUS";

      /* =========================
         STEP 2: HANDLE MALICIOUS FILE
      ========================= */

      if (malwareStatus === "MALICIOUS") {

        const quarantineName =
          `${Date.now()}-${originalname}`;

        const quarantinePath =
          path.join(
            QUARANTINE_DIR,
            quarantineName
          );

        fs.renameSync(
          tempPath,
          quarantinePath
        );

        await pool.query(
          `INSERT INTO secure_files
          (user_id,
           original_name,
           stored_name,
           mime_type,
           file_size,
           malware_status,
           malicious_count,
           file_hash)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [
            req.user.id,
            originalname,
            quarantineName,
            mimetype,
            Number(size),
            "MALICIOUS",
            scanResult.maliciousCount || 1,
            scanResult.hash || null
          ]
        );

        await logAuditEvent({
          userEmail: req.user.email,
          action: "malware_detected",
          status: "blocked",
          ipAddress: req.ip
        });

        return res.status(400).json({
          message:
            `Malware detected (${scanResult.maliciousCount} engines)`,
          engines:
            scanResult.engines,
          hash:
            scanResult.hash
        });

      }

      /* =========================
         STEP 3: ENCRYPT SAFE FILE
      ========================= */

      const storedName =
        `${Date.now()}-${originalname}`;

      const encryptedPath =
        path.join(
          VAULT_DIR,
          storedName
        );

      await encryptFile(
        tempPath,
        encryptedPath
      );

      fs.unlinkSync(tempPath);

      /* =========================
         STEP 4: SAVE DATABASE
      ========================= */

      await pool.query(
        `INSERT INTO secure_files
        (user_id,
         original_name,
         stored_name,
         mime_type,
         file_size,
         malware_status,
         malicious_count,
         file_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          req.user.id,
          originalname,
          storedName,
          mimetype,
          Number(size),
          malwareStatus,
          scanResult.maliciousCount || 0,
          scanResult.hash || null
        ]
      );

      /* =========================
         STEP 5: AUDIT LOG
      ========================= */

      await logAuditEvent({
        userEmail: req.user.email,
        action: "file_upload",
        status:
          malwareStatus === "SCAN_SKIPPED"
            ? "scan_skipped"
            : "success",
        ipAddress: req.ip
      });

      /* =========================
         SUCCESS RESPONSE
      ========================= */

      res.json({

        message:
          malwareStatus === "SCAN_SKIPPED"
            ? "File uploaded (scan skipped, AES encrypted)"
            : "File uploaded securely (AES encrypted + malware-free)",

        hash:
          scanResult.hash,

        scanMethod:
          scanResult.method,

        engines:
          scanResult.engines || 0

      });

    }
    catch (error) {

      console.error(
        "Upload error:",
        error
      );

      if (
        tempPath &&
        fs.existsSync(tempPath)
      ) {
        fs.unlinkSync(tempPath);
      }

      res.status(500).json({
        message:
          "Upload failed"
      });

    }

  }
);

/* =====================================================
   GET USER FILES
===================================================== */

router.get(
  "/my-files",
  verifyToken,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `SELECT
           id,
           original_name,
           mime_type,
           file_size,
           created_at,
           malware_status,
           malicious_count,
           file_hash
           FROM secure_files
           WHERE user_id=$1
           ORDER BY created_at DESC`,
          [req.user.id]
        );

      res.json(result.rows);

    }
    catch (error) {

      console.error(error);

      res.status(500).json({
        message:
          "Failed to fetch files"
      });

    }

  }
);

/* =====================================================
   DOWNLOAD FILE
===================================================== */

router.get(
  "/download/:id",
  verifyToken,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `SELECT *
           FROM secure_files
           WHERE id=$1 AND user_id=$2`,
          [
            req.params.id,
            req.user.id
          ]
        );

      if (!result.rows.length)
        return res.status(404).json({
          message: "File not found"
        });

      const file =
        result.rows[0];

      if (
        file.malware_status ===
        "MALICIOUS"
      ) {
        return res.status(403).json({
          message:
            "Blocked: Malware detected"
        });
      }

      const encryptedPath =
        path.join(
          VAULT_DIR,
          file.stored_name
        );

      const tempPath =
        path.join(
          os.tmpdir(),
          file.original_name
        );

      await decryptFile(
        encryptedPath,
        tempPath
      );

      res.download(
        tempPath,
        file.original_name,
        () =>
          fs.unlinkSync(tempPath)
      );

    }
    catch (error) {

      console.error(error);

      res.status(500).json({
        message:
          "Download failed"
      });

    }

  }
);

/* =====================================================
   DELETE FILE
===================================================== */

router.delete(
  "/delete/:id",
  verifyToken,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `SELECT stored_name,
                  malware_status
           FROM secure_files
           WHERE id=$1 AND user_id=$2`,
          [
            req.params.id,
            req.user.id
          ]
        );

      if (!result.rows.length)
        return res.status(404).json({
          message: "File not found"
        });

      const file =
        result.rows[0];

      const vaultPath =
        path.join(
          VAULT_DIR,
          file.stored_name
        );

      const quarantinePath =
        path.join(
          QUARANTINE_DIR,
          file.stored_name
        );

      if (fs.existsSync(vaultPath))
        fs.unlinkSync(vaultPath);

      if (fs.existsSync(quarantinePath))
        fs.unlinkSync(quarantinePath);

      await pool.query(
        `DELETE FROM secure_files
         WHERE id=$1`,
        [req.params.id]
      );

      res.json({
        message:
          "File deleted securely"
      });

    }
    catch (error) {

      console.error(error);

      res.status(500).json({
        message:
          "Delete failed"
      });

    }

  }
);

export default router;

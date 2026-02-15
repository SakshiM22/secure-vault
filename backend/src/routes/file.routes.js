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

const upload = multer({
  dest: "temp/",
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB limit
  }
});

/* =====================================================
   UPLOAD FILE (AI MALWARE SCAN + AES ENCRYPTION)
===================================================== */
router.post(
  "/upload",
  verifyToken,
  upload.single("file"),
  async (req, res) => {

    try {

      if (req.user.role === "admin") {

        return res.status(403).json({
          message: "Admins are not allowed to upload files."
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
        path: tempPath
      } = req.file;

      /* =========================
         STEP 1: AI MALWARE SCAN
      ========================= */

      const scanResult = await scanFileForMalware(tempPath);

      if (!scanResult.safe) {

        fs.unlinkSync(tempPath);

        // Save malware record in database
        await pool.query(
          `INSERT INTO secure_files
           (user_id, original_name, stored_name, mime_type, file_size, malware_status, malicious_count)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,

          [
            req.user.id,
            originalname,
            null,
            mimetype,
            Number(size),
            "MALICIOUS",
            scanResult.maliciousCount || 1
          ]
        );

        await logAuditEvent({
          userEmail: req.user.email,
          action: "malware_detected",
          status: "blocked",
          ipAddress: req.ip,
        });

        return res.status(400).json({
          message: "Malware detected. Upload blocked.",
          maliciousCount: scanResult.maliciousCount
        });
      }

      /* =========================
         STEP 2: AES ENCRYPTION
      ========================= */

      const vaultDir = "vault";

      if (!fs.existsSync(vaultDir)) {

        fs.mkdirSync(vaultDir);
      }

      const storedName =
        `${Date.now()}-${originalname}`;

      const encryptedPath =
        path.join(vaultDir, storedName);

      await encryptFile(
        tempPath,
        encryptedPath
      );

      fs.unlinkSync(tempPath);

      /* =========================
         STEP 3: SAVE TO DATABASE
      ========================= */

      await pool.query(
        `INSERT INTO secure_files
         (user_id, original_name, stored_name, mime_type, file_size, malware_status, malicious_count)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,

        [
          req.user.id,
          originalname,
          storedName,
          mimetype,
          Number(size),
          "SAFE",
          0
        ]
      );

      /* =========================
         STEP 4: AUDIT LOG
      ========================= */

      await logAuditEvent({
        userEmail: req.user.email,
        action: "file_upload",
        status: "success",
        ipAddress: req.ip,
      });

      res.json({
        message:
          "File uploaded securely and malware-free"
      });

    } catch (error) {

      console.error("Upload error:", error);

      res.status(500).json({
        message: "Upload failed"
      });
    }
  }
);

/* =====================================================
   GET USER FILES (WITH MALWARE STATUS)
===================================================== */
router.get(
  "/my-files",
  verifyToken,
  async (req, res) => {

    try {

      const result = await pool.query(

        `SELECT
           id,
           original_name,
           mime_type,
           file_size,
           created_at,
           malware_status,
           malicious_count
         FROM secure_files
         WHERE user_id = $1
         ORDER BY created_at DESC`,

        [req.user.id]
      );

      const files =
        result.rows.map(file => ({

          ...file,

          file_size:
            Number(file.file_size),

          malware_status:
            file.malware_status || "SAFE",

          malicious_count:
            file.malicious_count || 0

        }));

      res.json(files);

    } catch (error) {

      console.error(
        "Fetch files error:",
        error
      );

      res.status(500).json({
        message:
          "Failed to fetch files"
      });
    }
  }
);

/* =====================================================
   DOWNLOAD FILE (BLOCK MALICIOUS)
===================================================== */
router.get(
  "/download/:id",
  verifyToken,
  async (req, res) => {

    try {

      const result = await pool.query(

        `SELECT
           stored_name,
           original_name,
           mime_type,
           malware_status
         FROM secure_files
         WHERE id=$1 AND user_id=$2`,

        [req.params.id, req.user.id]
      );

      if (result.rows.length === 0) {

        return res.status(404).json({
          message: "File not found"
        });
      }

      const file = result.rows[0];

      if (file.malware_status === "MALICIOUS") {

        return res.status(403).json({
          message:
            "Download blocked. File contains malware."
        });
      }

      const encryptedPath =
        path.join("vault", file.stored_name);

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
        () => {

          fs.unlinkSync(tempPath);
        }
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Download failed"
      });
    }
  }
);

/* =====================================================
   PREVIEW FILE (BLOCK MALICIOUS)
===================================================== */
router.get(
  "/preview/:id",
  verifyToken,
  async (req, res) => {

    try {

      const result = await pool.query(

        `SELECT
           stored_name,
           original_name,
           mime_type,
           malware_status
         FROM secure_files
         WHERE id=$1 AND user_id=$2`,

        [req.params.id, req.user.id]
      );

      if (result.rows.length === 0) {

        return res.status(404).json({
          message: "File not found"
        });
      }

      const file = result.rows[0];

      if (file.malware_status === "MALICIOUS") {

        return res.status(403).json({
          message:
            "Preview blocked. File contains malware."
        });
      }

      const encryptedPath =
        path.join("vault", file.stored_name);

      const tempPath =
        path.join(
          os.tmpdir(),
          file.original_name
        );

      await decryptFile(
        encryptedPath,
        tempPath
      );

      res.sendFile(
        path.resolve(tempPath),
        () => {

          fs.unlinkSync(tempPath);
        }
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Preview failed"
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

      const result = await pool.query(

        `SELECT stored_name
         FROM secure_files
         WHERE id=$1 AND user_id=$2`,

        [req.params.id, req.user.id]
      );

      if (result.rows.length === 0) {

        return res.status(404).json({
          message: "File not found"
        });
      }

      const file = result.rows[0];

      if (file.stored_name) {

        const filePath =
          path.join("vault", file.stored_name);

        if (fs.existsSync(filePath)) {

          fs.unlinkSync(filePath);
        }
      }

      await pool.query(
        "DELETE FROM secure_files WHERE id=$1",
        [req.params.id]
      );

      res.json({
        message: "File deleted securely"
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Delete failed"
      });
    }
  }
);

export default router;

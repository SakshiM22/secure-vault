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
   MULTER CONFIG (1GB LIMIT)
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
   SHA256 + AI SCAN + AES ENCRYPTION + QUARANTINE
===================================================== */

router.post(
  "/upload",
  verifyToken,
  upload.single("file"),
  async (req, res) => {

    let tempPath = null;

    try {

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

      console.log("Scanning file for malware...");

      const scanResult =
        await scanFileForMalware(tempPath);

      console.log("Scan result:", scanResult);


      /* =====================================================
         DETERMINE STATUS
      ===================================================== */

      let malwareStatus = "SAFE";

      if (!scanResult.safe) {

        malwareStatus = "MALICIOUS";

      }
      else if (scanResult.skipped) {

        malwareStatus = "QUARANTINED";

      }


      /* =====================================================
         HANDLE MALICIOUS OR QUARANTINED FILE
      ===================================================== */

      if (
        malwareStatus === "MALICIOUS" ||
        malwareStatus === "QUARANTINED"
      ) {

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
          (
            user_id,
            original_name,
            stored_name,
            mime_type,
            file_size,
            malware_status,
            malicious_count,
            file_hash
          )
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

        await logAuditEvent({

          userEmail: req.user.email,
          action: "file_quarantined",
          status: malwareStatus.toLowerCase(),
          ipAddress: req.ip

        });

        return res.status(400).json({

          message:
            malwareStatus === "MALICIOUS"
              ? "Malware detected. File quarantined."
              : "File could not be scanned. Quarantined for safety.",

          status: malwareStatus,
          hash: scanResult.hash

        });

      }


      /* =====================================================
         SAFE FILE → AES ENCRYPT AND STORE
      ===================================================== */

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


      /* =====================================================
         SAVE SAFE FILE IN DATABASE
      ===================================================== */

      await pool.query(

        `INSERT INTO secure_files
        (
          user_id,
          original_name,
          stored_name,
          mime_type,
          file_size,
          malware_status,
          malicious_count,
          file_hash
        )
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


      /* =====================================================
         AUDIT LOG
      ===================================================== */

      await logAuditEvent({

        userEmail: req.user.email,
        action: "file_upload",
        status: "success",
        ipAddress: req.ip

      });


      res.json({

        message:
          "File uploaded securely (AES encrypted + malware-free)",

        hash: scanResult.hash,
        scanMethod: scanResult.method

      });

    }
    catch (error) {

      console.error("Upload error:", error);

      if (
        tempPath &&
        fs.existsSync(tempPath)
      ) {

        fs.unlinkSync(tempPath);

      }

      res.status(500).json({
        message: "Upload failed"
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
        message: "Failed to fetch files"
      });

    }

  }
);


/* =====================================================
   DOWNLOAD FILE (BLOCK QUARANTINED)
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

          [req.params.id, req.user.id]

        );

      if (!result.rows.length)

        return res.status(404).json({
          message: "File not found"
        });

      const file =
        result.rows[0];

      if (
        file.malware_status === "MALICIOUS" ||
        file.malware_status === "QUARANTINED"
      ) {

        return res.status(403).json({
          message:
            "File blocked for security reasons"
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
        message: "Download failed"
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

          `SELECT stored_name
           FROM secure_files
           WHERE id=$1 AND user_id=$2`,

          [req.params.id, req.user.id]

        );

      if (!result.rows.length)

        return res.status(404).json({
          message: "File not found"
        });

      const storedName =
        result.rows[0].stored_name;

      const vaultPath =
        path.join(
          VAULT_DIR,
          storedName
        );

      const quarantinePath =
        path.join(
          QUARANTINE_DIR,
          storedName
        );

      if (fs.existsSync(vaultPath))
        fs.unlinkSync(vaultPath);

      if (fs.existsSync(quarantinePath))
        fs.unlinkSync(quarantinePath);

      await pool.query(
        "DELETE FROM secure_files WHERE id=$1",
        [req.params.id]
      );

      res.json({
        message: "File deleted securely"
      });

    }
    catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Delete failed"
      });

    }

  }
);


export default router;

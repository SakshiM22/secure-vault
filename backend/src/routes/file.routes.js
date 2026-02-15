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
   ENSURE DIRECTORIES EXIST
===================================================== */

const VAULT_DIR = "vault";
const QUARANTINE_DIR = "quarantine";

if (!fs.existsSync(VAULT_DIR)) fs.mkdirSync(VAULT_DIR);
if (!fs.existsSync(QUARANTINE_DIR)) fs.mkdirSync(QUARANTINE_DIR);

/* =====================================================
   UPLOAD FILE (AI MALWARE SCAN + AES ENCRYPTION)
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

      /* =====================================================
         STEP 1: AI MALWARE SCAN
      ===================================================== */

      console.log("Scanning file for malware...");

      const scanResult =
        await scanFileForMalware(tempPath);

      console.log("Scan result:", scanResult);

      /* =====================================================
         STEP 2: HANDLE MALICIOUS FILE
      ===================================================== */

      if (!scanResult.safe) {

        const quarantineName =
          `${Date.now()}-${originalname}`;

        const quarantinePath =
          path.join(
            QUARANTINE_DIR,
            quarantineName
          );

        fs.renameSync(tempPath, quarantinePath);

        await pool.query(

          `INSERT INTO secure_files
           (user_id, original_name, stored_name, mime_type,
            file_size, malware_status, malicious_count)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,

          [
            req.user.id,
            originalname,
            quarantineName,
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
          ipAddress: req.ip

        });

        return res.status(400).json({

          message: `Malware detected (${scanResult.maliciousCount} engines)`,

          maliciousCount:
            scanResult.maliciousCount

        });
      }

      /* =====================================================
         STEP 3: AES ENCRYPT FILE
      ===================================================== */

      const storedName =
        `${Date.now()}-${originalname}`;

      const encryptedPath =
        path.join(VAULT_DIR, storedName);

      await encryptFile(
        tempPath,
        encryptedPath
      );

      fs.unlinkSync(tempPath);

      /* =====================================================
         STEP 4: SAVE SAFE FILE TO DATABASE
      ===================================================== */

      await pool.query(

        `INSERT INTO secure_files
         (user_id, original_name, stored_name,
          mime_type, file_size, malware_status, malicious_count)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,

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

      /* =====================================================
         STEP 5: AUDIT LOG
      ===================================================== */

      await logAuditEvent({

        userEmail: req.user.email,
        action: "file_upload",
        status: "success",
        ipAddress: req.ip

      });

      res.json({

        message:
          "File uploaded securely (AES encrypted + malware-free)"

      });

    }
    catch (error) {

      console.error("Upload error:", error);

      if (tempPath && fs.existsSync(tempPath)) {

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

          `SELECT id,
                  original_name,
                  mime_type,
                  file_size,
                  created_at,
                  malware_status,
                  malicious_count
           FROM secure_files
           WHERE user_id=$1
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

      if (!result.rows.length) {

        return res.status(404).json({

          message: "File not found"

        });
      }

      const file =
        result.rows[0];

      if (
        file.malware_status ===
        "MALICIOUS"
      ) {

        return res.status(403).json({

          message:
            "Blocked: malware detected"

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

          `SELECT stored_name
           FROM secure_files
           WHERE id=$1 AND user_id=$2`,

          [
            req.params.id,
            req.user.id
          ]
        );

      if (!result.rows.length) {

        return res.status(404).json({

          message: "File not found"

        });
      }

      const storedName =
        result.rows[0].stored_name;

      if (storedName) {

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

        if (
          fs.existsSync(vaultPath)
        )
          fs.unlinkSync(vaultPath);

        if (
          fs.existsSync(
            quarantinePath
          )
        )
          fs.unlinkSync(
            quarantinePath
          );
      }

      await pool.query(

        "DELETE FROM secure_files WHERE id=$1",

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

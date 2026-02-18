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
   MULTER CONFIG (1GB SUPPORT)
===================================================== */

const upload = multer({
  dest: "temp/",
  limits: {
    fileSize: 1024 * 1024 * 1024 // 1GB
  }
});


/* =====================================================
   DIRECTORY SETUP
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
   Enterprise workflow:
   SHA256 → Hash check → Scan → Encrypt OR Quarantine
===================================================== */

router.post(
  "/upload",
  verifyToken,
  upload.single("file"),
  async (req, res) => {

    let tempPath = null;

    try {

      if (!req.file)
        return res.status(400).json({
          message: "No file uploaded"
        });

      if (req.user.role === "admin")
        return res.status(403).json({
          message: "Admins cannot upload files"
        });


      const {
        originalname,
        mimetype,
        size,
        path: uploadedTempPath
      } = req.file;

      tempPath = uploadedTempPath;

      console.log("=================================");
      console.log("Starting malware scan...");
      console.log("File:", originalname);
      console.log("Size:", size);
      console.log("=================================");


      /* =====================================================
         STEP 1: MALWARE SCAN
      ===================================================== */

      const scanResult =
        await scanFileForMalware(tempPath);

      console.log("Scan result:", scanResult);


      /* =====================================================
         STEP 2: DETERMINE FINAL STATUS
      ===================================================== */

      let malwareStatus;
      let shouldQuarantine = false;

      if (scanResult.safe === false) {

        malwareStatus = "MALICIOUS";
        shouldQuarantine = true;

      }
      else if (scanResult.skipped === true) {

        malwareStatus = "UNSCANNED";
        shouldQuarantine = true;

      }
      else {

        malwareStatus = "SAFE";

      }


      /* =====================================================
         STEP 3: QUARANTINE MALICIOUS OR UNSCANNED FILE
      ===================================================== */

      if (shouldQuarantine) {

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

          action:
            malwareStatus === "MALICIOUS"
              ? "malware_detected"
              : "file_unscanned",

          status: malwareStatus.toLowerCase(),

          ipAddress: req.ip

        });


        return res.status(400).json({

          message:
            malwareStatus === "MALICIOUS"
              ? "Malware detected. File quarantined."
              : "File not scanned. Stored in quarantine.",

          status: malwareStatus,

          hash: scanResult.hash,

          scanMethod: scanResult.method

        });

      }


      /* =====================================================
         STEP 4: SAFE FILE → ENCRYPT AND STORE
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
         STEP 5: SAVE SAFE FILE IN DATABASE
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
         STEP 6: AUDIT LOG
      ===================================================== */

      await logAuditEvent({

        userEmail: req.user.email,

        action: "file_upload",

        status: "success",

        ipAddress: req.ip

      });


      res.json({

        message:
          "File uploaded securely (AES-256 encrypted + malware-free)",

        hash: scanResult.hash,

        scanMethod: scanResult.method,

        engines: scanResult.engines || 0

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



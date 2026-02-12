import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import os from "os";

import { verifyToken } from "../middleware/auth.middleware.js";
import pool from "../config/db.js";
import { encryptFile, decryptFile } from "../utils/crypto/fileCrypto.js";
import { logAuditEvent } from "../utils/auditLogger.js";

const router = express.Router();
const upload = multer({ dest: "temp/" });

/* =========================
   UPLOAD FILE (ENCRYPT)
   ========================= */
router.post(
  "/upload",
  verifyToken,
  upload.single("file"),
  async (req, res) => {
    try {

      /* 🚫 BLOCK ADMIN FROM UPLOADING */
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

      const { originalname, mimetype, size, path: tempPath } = req.file;

      /* Ensure vault directory exists */
      const encryptedDir = "vault";

      if (!fs.existsSync(encryptedDir)) {
        fs.mkdirSync(encryptedDir);
      }

      const storedName = `${Date.now()}-${originalname}`;
      const encryptedPath = path.join(encryptedDir, storedName);

      /* Encrypt file */
      await encryptFile(tempPath, encryptedPath);

      /* Remove temp file */
      fs.unlinkSync(tempPath);

      /* Save in database */
      await pool.query(
        `INSERT INTO secure_files
         (user_id, original_name, stored_name, mime_type, file_size)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          req.user.id,
          originalname,
          storedName,
          mimetype,
          Number(size)
        ]
      );

      /* Audit log */
      await logAuditEvent({
        userEmail: req.user.email,
        action: "file_upload",
        status: "success",
        ipAddress: req.ip,
      });

      res.json({
        message: "File uploaded securely"
      });

    } catch (error) {

      console.error("Upload error:", error);

      res.status(500).json({
        message: "Upload failed"
      });
    }
  }
);


/* =========================
   LIST USER FILES
   ========================= */
router.get("/my-files", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, original_name, mime_type, file_size, created_at
       FROM secure_files
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    // 🔥 FIX: convert bigint string → number
    const files = result.rows.map(file => ({
      ...file,
      file_size: Number(file.file_size)
    }));

    return res.json(files);

  } catch (error) {
    console.error("Fetch files error:", error);
    return res.status(500).json({ message: "Failed to fetch files" });
  }
});


/* =========================
   DOWNLOAD FILE (DECRYPT)
   ========================= */
router.get("/download/:id", verifyToken, async (req, res) => {
  try {
    const fileId = req.params.id;

    const result = await pool.query(
      `SELECT stored_name, original_name, mime_type
       FROM secure_files
       WHERE id = $1 AND user_id = $2`,
      [fileId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ message: "Access denied" });
    }

    const file = result.rows[0];
    const encryptedPath = path.join("vault", file.stored_name);

    const tempDecryptedPath = path.join(
      os.tmpdir(),
      `${Date.now()}-${file.original_name}`
    );

    await decryptFile(encryptedPath, tempDecryptedPath);

    res.download(tempDecryptedPath, file.original_name, async () => {
      fs.unlinkSync(tempDecryptedPath);

      await logAuditEvent({
        userEmail: req.user.email, // ✅ FIXED
        action: "file_download",
        status: "success",
        ipAddress: req.ip,
      });
    });
  } catch (error) {
    console.error("Download error:", error);
    return res.status(500).json({ message: "Download failed" });
  }
});

/* =========================
   DELETE FILE (SECURE)
   ========================= */
router.delete("/delete/:id", verifyToken, async (req, res) => {
  try {
    const fileId = req.params.id;

    const result = await pool.query(
      `SELECT stored_name
       FROM secure_files
       WHERE id = $1 AND user_id = $2`,
      [fileId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ message: "Access denied" });
    }

    const { stored_name } = result.rows[0];
    const encryptedPath = path.join("vault", stored_name);

    if (fs.existsSync(encryptedPath)) {
      fs.unlinkSync(encryptedPath);
    }

    await pool.query(
      `DELETE FROM secure_files WHERE id = $1`,
      [fileId]
    );

    await logAuditEvent({
      userEmail: req.user.email, // ✅ FIXED
      action: "file_delete",
      status: "success",
      ipAddress: req.ip,
    });

    return res.json({ message: "File deleted securely" });
  } catch (error) {
    console.error("Delete error:", error);
    return res.status(500).json({ message: "Delete failed" });
  }
});

/* =========================
   PREVIEW FILE
   ========================= */
router.get("/preview/:id", verifyToken, async (req, res) => {
  try {
    const fileId = req.params.id;

    const result = await pool.query(
      `SELECT original_name, stored_name, mime_type
       FROM secure_files
       WHERE id = $1 AND user_id = $2`,
      [fileId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ message: "Access denied" });
    }

    const { stored_name, mime_type, original_name } = result.rows[0];

    const encryptedPath = path.join("vault", stored_name);
    const tempDecryptedPath = path.join(
      os.tmpdir(),
      `preview-${Date.now()}-${original_name}`
    );

    await decryptFile(encryptedPath, tempDecryptedPath);

    res.setHeader("Content-Type", mime_type);
    res.setHeader("Content-Disposition", "inline");

    res.sendFile(path.resolve(tempDecryptedPath), async () => {
      fs.unlink(tempDecryptedPath, () => {});

      await logAuditEvent({
        userEmail: req.user.email, // ✅ Added logging
        action: "file_preview",
        status: "success",
        ipAddress: req.ip,
        req,
      });
    });

  } catch (error) {
    console.error("Preview error:", error);
    res.status(500).json({ message: "Preview failed" });
  }
});

export default router;

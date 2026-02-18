import express from "express";
import pool from "../config/db.js";
import { verifyToken } from "../middleware/auth.middleware.js";
import { allowRoles } from "../middleware/role.middleware.js";

import fs from "fs";
import path from "path";

const router = express.Router();


/* =====================================================
   AUDIT LOGS
===================================================== */
router.get(
  "/audit-logs",
  verifyToken,
  allowRoles("admin"),
  async (req, res) => {

    try {

      const result = await pool.query(`
        SELECT
          id,
          user_email,
          action,
          status,
          ip_address,
          created_at
        FROM audit_logs
        ORDER BY created_at DESC
        LIMIT 500
      `);

      res.json(result.rows);

    }
    catch (error) {

      console.error("Audit logs error:", error);

      res.status(500).json({
        message: "Failed to fetch audit logs"
      });

    }

  }
);



/* =====================================================
   ENTERPRISE SECURITY ANALYTICS
===================================================== */
router.get(
  "/analytics",
  verifyToken,
  allowRoles("admin"),
  async (req, res) => {

    try {

      const [
        totalUsers,
        lockedAccounts,
        safeFiles,
        malwareFiles,
        skippedFiles,
        totalDownloads,
        failedLogins24h,
        locks24h
      ] = await Promise.all([

        pool.query(`SELECT COUNT(*) FROM users`),

        pool.query(`
          SELECT COUNT(*) FROM users
          WHERE is_locked=true
        `),

        pool.query(`
          SELECT COUNT(*) FROM secure_files
          WHERE malware_status='SAFE'
        `),

        pool.query(`
          SELECT COUNT(*) FROM secure_files
          WHERE malware_status='MALICIOUS'
        `),

        pool.query(`
          SELECT COUNT(*) FROM secure_files
          WHERE malware_status='SCAN_SKIPPED'
          OR malware_status='QUARANTINED'
        `),

        pool.query(`
          SELECT COUNT(*) FROM audit_logs
          WHERE action='file_download'
        `),

        pool.query(`
          SELECT COUNT(*) FROM audit_logs
          WHERE action='login'
          AND status='failed'
          AND created_at >= NOW() - INTERVAL '24 hours'
        `),

        pool.query(`
          SELECT COUNT(*) FROM audit_logs
          WHERE action='account_lock'
          AND created_at >= NOW() - INTERVAL '24 hours'
        `)

      ]);


      const safeCount =
        Number(safeFiles.rows[0].count);

      const malwareCount =
        Number(malwareFiles.rows[0].count);

      const skippedCount =
        Number(skippedFiles.rows[0].count);


      const totalUploads =
        safeCount +
        malwareCount +
        skippedCount;


      res.json({

        totalUsers:
          Number(totalUsers.rows[0].count),

        lockedAccounts:
          Number(lockedAccounts.rows[0].count),

        totalUploads: totalUploads,

        safeFiles: safeCount,

        malwareFiles: malwareCount,

        skippedFiles: skippedCount,

        totalDownloads:
          Number(totalDownloads.rows[0].count),

        failedLogins24h:
          Number(failedLogins24h.rows[0].count),

        locks24h:
          Number(locks24h.rows[0].count)

      });

    }
    catch (error) {

      console.error("Analytics error:", error);

      res.status(500).json({
        message: "Analytics failed"
      });

    }

  }
);



/* =====================================================
   MALWARE FILES
===================================================== */
router.get(
  "/malware-files",
  verifyToken,
  allowRoles("admin"),
  async (req, res) => {

    try {

      const result = await pool.query(`
        SELECT
          sf.id,
          sf.original_name,
          sf.file_hash,
          sf.file_size,
          sf.malicious_count,
          sf.malware_status,
          sf.created_at,
          u.email as user_email
        FROM secure_files sf
        JOIN users u ON sf.user_id = u.id
        WHERE sf.malware_status='MALICIOUS'
        ORDER BY sf.created_at DESC
      `);

      res.json(result.rows);

    }
    catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Failed to fetch malware files"
      });

    }

  }
);



/* =====================================================
   SCAN SKIPPED / QUARANTINED FILES
===================================================== */
router.get(
  "/skipped-files",
  verifyToken,
  allowRoles("admin"),
  async (req, res) => {

    try {

      const result = await pool.query(`
        SELECT
          sf.id,
          sf.original_name,
          sf.file_hash,
          sf.file_size,
          sf.malware_status,
          sf.created_at,
          u.email as user_email
        FROM secure_files sf
        JOIN users u ON sf.user_id = u.id
        WHERE sf.malware_status='SCAN_SKIPPED'
        OR sf.malware_status='QUARANTINED'
        ORDER BY sf.created_at DESC
      `);

      res.json(result.rows);

    }
    catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Failed to fetch skipped files"
      });

    }

  }
);



/* =====================================================
   ALL FILES OVERVIEW
===================================================== */
router.get(
  "/all-files",
  verifyToken,
  allowRoles("admin"),
  async (req, res) => {

    try {

      const result = await pool.query(`
        SELECT
          sf.id,
          sf.original_name,
          sf.file_hash,
          sf.file_size,
          sf.malware_status,
          sf.malicious_count,
          sf.created_at,
          u.email as user_email
        FROM secure_files sf
        JOIN users u ON sf.user_id = u.id
        ORDER BY sf.created_at DESC
      `);

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
   VAULT FILES (FILESYSTEM)
===================================================== */
router.get(
  "/vault-files",
  verifyToken,
  allowRoles("admin"),
  async (req, res) => {

    try {

      const vaultPath =
        path.join(process.cwd(), "vault");

      if (!fs.existsSync(vaultPath))
        return res.json([]);

      const files =
        fs.readdirSync(vaultPath);

      res.json(files);

    }
    catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Failed to fetch vault files"
      });

    }

  }
);



/* =====================================================
   USERS LIST
===================================================== */
router.get(
  "/users",
  verifyToken,
  allowRoles("admin"),
  async (req, res) => {

    try {

      const result = await pool.query(`
        SELECT
          id,
          email,
          role,
          is_locked,
          failed_attempts
        FROM users
        ORDER BY id ASC
      `);

      res.json(result.rows);

    }
    catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Failed"
      });

    }

  }
);



/* =====================================================
   LOCK USER
===================================================== */
router.patch(
  "/users/:id/lock",
  verifyToken,
  allowRoles("admin"),
  async (req, res) => {

    try {

      await pool.query(
        `UPDATE users SET is_locked=true WHERE id=$1`,
        [req.params.id]
      );

      res.json({
        message: "User locked"
      });

    }
    catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Lock failed"
      });

    }

  }
);



/* =====================================================
   UNLOCK USER
===================================================== */
router.patch(
  "/users/:id/unlock",
  verifyToken,
  allowRoles("admin"),
  async (req, res) => {

    try {

      await pool.query(
        `UPDATE users SET is_locked=false WHERE id=$1`,
        [req.params.id]
      );

      res.json({
        message: "User unlocked"
      });

    }
    catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Unlock failed"
      });

    }

  }
);



export default router;

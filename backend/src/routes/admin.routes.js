import express from "express";
import pool from "../config/db.js";
import { verifyToken } from "../middleware/auth.middleware.js";
import { allowRoles } from "../middleware/role.middleware.js";
import { logAuditEvent } from "../utils/auditLogger.js";

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

    } catch (error) {

      console.error("Audit logs error:", error);

      res.status(500).json({
        message: "Failed to fetch audit logs"
      });

    }

  }
);

/* =====================================================
   SECURITY ANALYTICS
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
        totalUploads,
        totalDownloads,
        failedLogins24h,
        locks24h,
        malwareFiles
      ] = await Promise.all([

        pool.query(`SELECT COUNT(*) FROM users`),

        pool.query(`
          SELECT COUNT(*)
          FROM users
          WHERE is_locked = true
        `),

        pool.query(`
          SELECT COUNT(*)
          FROM secure_files
          WHERE malware_status = 'SAFE'
        `),

        pool.query(`
          SELECT COUNT(*)
          FROM audit_logs
          WHERE action = 'file_download'
        `),

        pool.query(`
          SELECT COUNT(*)
          FROM audit_logs
          WHERE action='login'
          AND status='failed'
          AND created_at >= NOW() - INTERVAL '24 hours'
        `),

        pool.query(`
          SELECT COUNT(*)
          FROM audit_logs
          WHERE action='account_lock'
          AND created_at >= NOW() - INTERVAL '24 hours'
        `),

        pool.query(`
          SELECT COUNT(*)
          FROM secure_files
          WHERE malware_status='MALICIOUS'
        `)

      ]);

      res.json({

        totalUsers: Number(totalUsers.rows[0].count),

        lockedAccounts: Number(lockedAccounts.rows[0].count),

        totalUploads: Number(totalUploads.rows[0].count),

        totalDownloads: Number(totalDownloads.rows[0].count),

        failedLogins24h: Number(failedLogins24h.rows[0].count),

        locks24h: Number(locks24h.rows[0].count),

        malwareFiles: Number(malwareFiles.rows[0].count)

      });

    } catch (error) {

      console.error("Analytics error:", error);

      res.status(500).json({
        message: "Analytics failed"
      });

    }

  }
);

/* =====================================================
   MALWARE FILES (FIXED)
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
          sf.user_id,
          u.email AS user_email,
          sf.malware_status,
          sf.malicious_count,
          sf.created_at
        FROM secure_files sf
        JOIN users u ON sf.user_id = u.id
        WHERE sf.malware_status = 'MALICIOUS'
        ORDER BY sf.created_at DESC
      `);

      res.json(result.rows);

    } catch (error) {

      console.error("Malware files error:", error);

      res.status(500).json({
        message: "Failed to fetch malware files"
      });

    }

  }
);

/* =====================================================
   SUSPICIOUS ACTIVITY
===================================================== */
router.get(
  "/suspicious-activity",
  verifyToken,
  allowRoles("admin"),
  async (req, res) => {

    try {

      const failedLoginUsers = await pool.query(`
        SELECT
          user_email,
          COUNT(*) AS failed_count
        FROM audit_logs
        WHERE action='login'
        AND status='failed'
        GROUP BY user_email
        HAVING COUNT(*) > 5
        ORDER BY failed_count DESC
      `);

      const suspiciousIPs = await pool.query(`
        SELECT
          ip_address,
          COUNT(*) AS attempts
        FROM audit_logs
        WHERE action='login'
        AND status='failed'
        GROUP BY ip_address
        HAVING COUNT(*) > 10
      `);

      const recentLocks = await pool.query(`
        SELECT
          user_email,
          created_at
        FROM audit_logs
        WHERE action='account_lock'
        ORDER BY created_at DESC
        LIMIT 20
      `);

      res.json({

        failedLoginUsers: failedLoginUsers.rows,

        suspiciousIPs: suspiciousIPs.rows,

        recentLocks: recentLocks.rows,

        highUploadUsers: []

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Failed to fetch suspicious activity"
      });

    }

  }
);

/* =====================================================
   GET USERS
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
          failed_attempts,
          token_version
        FROM users
        ORDER BY id ASC
      `);

      res.json(result.rows);

    } catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Failed to fetch users"
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

      const id = Number(req.params.id);

      if (id === req.user.id)
        return res.status(400).json({
          message: "Cannot lock yourself"
        });

      await pool.query(`
        UPDATE users
        SET is_locked=true,
        lock_time=NOW()
        WHERE id=$1
      `, [id]);

      res.json({
        message: "User locked"
      });

    } catch (error) {

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

      await pool.query(`
        UPDATE users
        SET is_locked=false,
        failed_attempts=0
        WHERE id=$1
      `, [req.params.id]);

      res.json({
        message: "User unlocked"
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Unlock failed"
      });

    }

  }
);

/* =====================================================
   DELETE USER
===================================================== */
router.delete(
  "/users/:id",
  verifyToken,
  allowRoles("admin"),
  async (req, res) => {

    const client = await pool.connect();

    try {

      const id = Number(req.params.id);

      if (id === req.user.id)
        return res.status(400).json({
          message: "Cannot delete yourself"
        });

      await client.query("BEGIN");

      await client.query(
        "DELETE FROM secure_files WHERE user_id=$1",
        [id]
      );

      await client.query(
        "DELETE FROM audit_logs WHERE user_email=(SELECT email FROM users WHERE id=$1)",
        [id]
      );

      await client.query(
        "DELETE FROM users WHERE id=$1",
        [id]
      );

      await client.query("COMMIT");

      res.json({
        message: "User deleted"
      });

    } catch (error) {

      await client.query("ROLLBACK");

      console.error(error);

      res.status(500).json({
        message: "Delete failed"
      });

    } finally {

      client.release();

    }

  }
);

export default router;

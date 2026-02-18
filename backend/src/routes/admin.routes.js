import express from "express";
import pool from "../config/db.js";
import { verifyToken } from "../middleware/auth.middleware.js";
import { allowRoles } from "../middleware/role.middleware.js";

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

      res.json({

        totalUsers: Number(totalUsers.rows[0].count),

        lockedAccounts: Number(lockedAccounts.rows[0].count),

        safeFiles: Number(safeFiles.rows[0].count),

        malwareFiles: Number(malwareFiles.rows[0].count),

        skippedFiles: Number(skippedFiles.rows[0].count),

        totalDownloads: Number(totalDownloads.rows[0].count),

        failedLogins24h: Number(failedLogins24h.rows[0].count),

        locks24h: Number(locks24h.rows[0].count)

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
   MALWARE FILES LIST (FULL DETAILS)
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

    } catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Failed to fetch malware files"
      });

    }
  }
);


/* =====================================================
   SCAN SKIPPED FILES (IMPORTANT)
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
          sf.created_at,
          u.email as user_email
        FROM secure_files sf
        JOIN users u ON sf.user_id = u.id
        WHERE sf.malware_status='SCAN_SKIPPED'
        ORDER BY sf.created_at DESC
      `);

      res.json(result.rows);

    } catch (error) {

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

    } catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Failed to fetch files"
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
        SELECT user_email, COUNT(*) as failed_count
        FROM audit_logs
        WHERE action='login'
        AND status='failed'
        GROUP BY user_email
        HAVING COUNT(*) > 5
      `);

      const suspiciousIPs = await pool.query(`
        SELECT ip_address, COUNT(*) as attempts
        FROM audit_logs
        WHERE action='login'
        AND status='failed'
        GROUP BY ip_address
        HAVING COUNT(*) > 10
      `);

      res.json({
        failedLoginUsers: failedLoginUsers.rows,
        suspiciousIPs: suspiciousIPs.rows
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        message: "Failed"
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
        SELECT id,email,role,is_locked,failed_attempts
        FROM users
        ORDER BY id ASC
      `);

      res.json(result.rows);

    } catch (error) {

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

    await pool.query(
      `UPDATE users SET is_locked=true WHERE id=$1`,
      [req.params.id]
    );

    res.json({
      message: "User locked"
    });
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

    await pool.query(
      `UPDATE users SET is_locked=false WHERE id=$1`,
      [req.params.id]
    );

    res.json({
      message: "User unlocked"
    });
  }
);

/* =====================================================
  Endpoint to receive vault files for admin review
===================================================== */
router.get("/vault-files", verifyToken, allowRoles("admin"), async (req, res) => {

  const vaultPath = path.join(process.cwd(), "vault");

  if (!fs.existsSync(vaultPath))
    return res.json([]);

  const files = fs.readdirSync(vaultPath);

  res.json(files);

});



export default router;

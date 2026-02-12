import pool from "../config/db.js";

/**
 * Logs audit event + emits real-time update to admin dashboard
 */
export const logAuditEvent = async ({
  userEmail,
  action,
  status,
  ipAddress,
  req, // 👈 we will pass request object now
}) => {
  try {
    const result = await pool.query(
      `INSERT INTO audit_logs (user_email, action, status, ip_address)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [userEmail, action, status, ipAddress]
    );

    const newLog = result.rows[0];

    // 🔌 Emit real-time event to connected admins
    if (req) {
      const io = req.app.get("io");
      if (io) {
        io.emit("audit:new", newLog);
      }
    }

  } catch (error) {
    console.error("Audit log failed:", error.message);
  }
};

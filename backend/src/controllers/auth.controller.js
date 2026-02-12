import pool from "../config/db.js";
import jwt from "jsonwebtoken";
import { comparePassword, hashPassword } from "../utils/password.js";
import { logAuditEvent } from "../utils/auditLogger.js";

const MAX_ATTEMPTS = 3;
const LOCK_TIME_MINUTES = 30;

/* ===========================
   LOGIN CONTROLLER
   =========================== */
export const login = async (req, res) => {
  const { email, password } = req.body;
  const ipAddress = req.ip;

  try {
    const userRes = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (userRes.rows.length === 0) {
      await logAuditEvent({
        userEmail: email,
        action: "login",
        status: "failed",
        ipAddress,
      });

      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = userRes.rows[0];

    /* =================================================
       🔒 ACCOUNT LOCK CHECK (ADMIN vs BRUTE FORCE)
    ================================================== */

    if (user.is_locked) {

      // 🛑 ADMIN LOCK (no lock_time set)
      if (user.is_locked) {
  await logAuditEvent({
    userEmail: user.email,
    action: "login",
    status: "locked",
    ipAddress,
  });

  return res.status(423).json({
    message: "Account is locked by administrator.",
  });
}


      // ⏳ BRUTE FORCE LOCK (temporary)
      const lockDuration =
        (Date.now() - new Date(user.lock_time)) / (1000 * 60);

      if (lockDuration < LOCK_TIME_MINUTES) {
        await logAuditEvent({
          userEmail: user.email,
          action: "login",
          status: "locked",
          ipAddress,
        });

        return res.status(423).json({
          message: "Account temporarily locked",
        });
      }

      // 🔓 Auto unlock after cooldown
      await pool.query(
        "UPDATE users SET is_locked=false, failed_attempts=0, lock_time=NULL WHERE id=$1",
        [user.id]
      );
    }

    /* =================================================
       🔐 PASSWORD VALIDATION
    ================================================== */

    const validPassword = await comparePassword(password, user.password);

    if (!validPassword) {
      const attempts = user.failed_attempts + 1;

      if (attempts >= MAX_ATTEMPTS) {
        await pool.query(
          "UPDATE users SET failed_attempts=$1, is_locked=true, lock_time=NOW() WHERE id=$2",
          [attempts, user.id]
        );

        await logAuditEvent({
          userEmail: user.email,
          action: "account_lock",
          status: "locked",
          ipAddress,
        });

        return res.status(423).json({
          message: "Account temporarily locked",
        });
      }

      await pool.query(
        "UPDATE users SET failed_attempts=$1 WHERE id=$2",
        [attempts, user.id]
      );

      await logAuditEvent({
        userEmail: user.email,
        action: "login",
        status: "failed",
        ipAddress,
      });

      return res.status(401).json({ message: "Invalid credentials" });
    }

    /* =================================================
       ✅ SUCCESSFUL LOGIN
    ================================================== */

    await pool.query(
      "UPDATE users SET failed_attempts=0 WHERE id=$1",
      [user.id]
    );

    const token = jwt.sign(
      {
        id: user.id,
        role: user.role,
        email: user.email,
        tokenVersion: user.token_version,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    await logAuditEvent({
      userEmail: user.email,
      action: "login",
      status: "success",
      ipAddress,
    });

    return res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });

  } catch (error) {
    console.error("Login error:", error);

    await logAuditEvent({
      userEmail: email,
      action: "login",
      status: "error",
      ipAddress,
    });

    return res.status(500).json({ message: "Server error" });
  }
};

/* ===========================
   SIGNUP CONTROLLER
   =========================== */
export const signup = async (req, res) => {
  const { email, password } = req.body;
  const ipAddress = req.ip;

  if (!email || !password) {
    return res.status(400).json({ message: "Invalid input" });
  }

  try {
    const hashedPassword = await hashPassword(password);

    await pool.query(
      "INSERT INTO users (email, password, role) VALUES ($1, $2, 'user')",
      [email, hashedPassword]
    );

    await logAuditEvent({
      userEmail: email,
      action: "signup",
      status: "success",
      ipAddress,
    });

    return res.status(201).json({
      message: "Signup successful",
    });

  } catch (error) {
    console.error("Signup error:", error);

    if (error.code === "23505") {
      await logAuditEvent({
        userEmail: email,
        action: "signup",
        status: "failed",
        ipAddress,
      });

      return res.status(409).json({
        message: "User already exists",
      });
    }

    await logAuditEvent({
      userEmail: email,
      action: "signup",
      status: "error",
      ipAddress,
    });

    return res.status(500).json({
      message: "Server error",
    });
  }
};

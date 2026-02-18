import pool from "../config/db.js";
import jwt from "jsonwebtoken";
import { comparePassword, hashPassword } from "../utils/password.js";
import { logAuditEvent } from "../utils/auditLogger.js";

const MAX_ATTEMPTS = 3;
const LOCK_TIME_MINUTES = 30;


/* =====================================================
   LOGIN CONTROLLER (ROLE-BASED SECURE LOGIN)
===================================================== */

export const login = async (req, res) => {

  const { email, password, role } = req.body;
  const ipAddress = req.ip;

  try {

    /* ==========================================
       FETCH USER
    ========================================== */

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (result.rows.length === 0) {

      await logAuditEvent({
        userEmail: email,
        action: "login",
        status: "failed_user_not_found",
        ipAddress,
      });

      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const user = result.rows[0];


    /* ==========================================
       ROLE VALIDATION (CRITICAL SECURITY FIX)
    ========================================== */

    if (role && user.role !== role) {

      await logAuditEvent({
        userEmail: user.email,
        action: "login",
        status: "failed_role_mismatch",
        ipAddress,
      });

      return res.status(403).json({
        message: "Access denied: incorrect role selected"
      });
    }


    /* ==========================================
       ACCOUNT LOCK CHECK
    ========================================== */

    if (user.is_locked) {

      // Check if temporary lock expired

      if (user.lock_time) {

        const lockDuration =
          (Date.now() - new Date(user.lock_time)) / (1000 * 60);

        if (lockDuration >= LOCK_TIME_MINUTES) {

          // Auto unlock
          await pool.query(
            `UPDATE users
             SET is_locked=false,
                 failed_attempts=0,
                 lock_time=NULL
             WHERE id=$1`,
            [user.id]
          );

        }
        else {

          await logAuditEvent({
            userEmail: user.email,
            action: "login",
            status: "blocked_locked",
            ipAddress,
          });

          return res.status(423).json({
            message: "Account temporarily locked"
          });
        }

      }
      else {

        // Admin lock (permanent)

        await logAuditEvent({
          userEmail: user.email,
          action: "login",
          status: "blocked_admin_lock",
          ipAddress,
        });

        return res.status(423).json({
          message: "Account locked by administrator"
        });

      }
    }


    /* ==========================================
       PASSWORD VALIDATION
    ========================================== */

    const passwordValid =
      await comparePassword(password, user.password);

    if (!passwordValid) {

      const attempts =
        user.failed_attempts + 1;

      if (attempts >= MAX_ATTEMPTS) {

        await pool.query(
          `UPDATE users
           SET failed_attempts=$1,
               is_locked=true,
               lock_time=NOW()
           WHERE id=$2`,
          [attempts, user.id]
        );

        await logAuditEvent({
          userEmail: user.email,
          action: "account_locked_bruteforce",
          status: "locked",
          ipAddress,
        });

        return res.status(423).json({
          message: "Account locked due to multiple failed attempts"
        });
      }

      await pool.query(
        "UPDATE users SET failed_attempts=$1 WHERE id=$2",
        [attempts, user.id]
      );

      await logAuditEvent({
        userEmail: user.email,
        action: "login",
        status: "failed_wrong_password",
        ipAddress,
      });

      return res.status(401).json({
        message: "Invalid email or password"
      });
    }


    /* ==========================================
       SUCCESS LOGIN
    ========================================== */

    await pool.query(
      "UPDATE users SET failed_attempts=0 WHERE id=$1",
      [user.id]
    );


    const token = jwt.sign(

      {
        id: user.id,
        email: user.email,
        role: user.role,
        tokenVersion: user.token_version
      },

      process.env.JWT_SECRET,

      {
        expiresIn: "1h"
      }

    );


    await logAuditEvent({
      userEmail: user.email,
      action: "login",
      status: "success",
      ipAddress,
    });


    return res.json({

      message: "Login successful",

      token,

      user: {

        id: user.id,
        email: user.email,
        role: user.role

      }

    });

  }
  catch (error) {

    console.error("Login error:", error);

    await logAuditEvent({
      userEmail: email,
      action: "login",
      status: "error",
      ipAddress,
    });

    return res.status(500).json({
      message: "Server error"
    });

  }

};


/* =====================================================
   SIGNUP CONTROLLER
===================================================== */

export const signup = async (req, res) => {

  const { email, password } = req.body;
  const ipAddress = req.ip;

  try {

    if (!email || !password) {

      return res.status(400).json({
        message: "Email and password required"
      });

    }


    const hashedPassword =
      await hashPassword(password);


    await pool.query(

      `INSERT INTO users
       (email, password, role)
       VALUES ($1,$2,'user')`,

      [email, hashedPassword]

    );


    await logAuditEvent({
      userEmail: email,
      action: "signup",
      status: "success",
      ipAddress,
    });


    return res.status(201).json({
      message: "Signup successful"
    });

  }
  catch (error) {

    console.error("Signup error:", error);

    if (error.code === "23505") {

      await logAuditEvent({
        userEmail: email,
        action: "signup",
        status: "duplicate",
        ipAddress,
      });

      return res.status(409).json({
        message: "User already exists"
      });

    }

    await logAuditEvent({
      userEmail: email,
      action: "signup",
      status: "error",
      ipAddress,
    });

    return res.status(500).json({
      message: "Server error"
    });

  }

};

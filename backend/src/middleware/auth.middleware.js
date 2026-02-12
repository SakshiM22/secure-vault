import jwt from "jsonwebtoken";
import pool from "../config/db.js";

export const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Access denied. No token provided.",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const userRes = await pool.query(
      "SELECT id, role, email, token_version FROM users WHERE id=$1",
      [decoded.id]
    );

    if (userRes.rows.length === 0) {
      return res.status(401).json({
        message: "User no longer exists.",
      });
    }

    const user = userRes.rows[0];

    // 🔐 TOKEN VERSION CHECK (Force logout logic)
    if (user.token_version !== decoded.tokenVersion) {
      return res.status(401).json({
        message: "Session invalidated. Please login again.",
      });
    }

    req.user = {
      id: user.id,
      role: user.role,
      email: user.email,
    };

    next();
  } catch (error) {
    return res.status(401).json({
      message: "Invalid or expired token.",
    });
  }
};

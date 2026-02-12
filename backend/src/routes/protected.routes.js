import express from "express";
import { verifyToken } from "../middleware/auth.middleware.js";
import { allowRoles } from "../middleware/role.middleware.js";

const router = express.Router();

/* ======================
   USER DASHBOARD
   ====================== */
router.get("/dashboard", verifyToken, (req, res) => {
  res.json({
    message: "Welcome to user dashboard",
    user: req.user,
  });
});

/* ======================
   ADMIN ONLY ROUTE
   ====================== */
router.get(
  "/admin",
  verifyToken,
  allowRoles("admin"),
  (req, res) => {
    res.json({
      message: "Welcome Admin",
    });
  }
);

export default router;

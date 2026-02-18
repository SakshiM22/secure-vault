import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import http from "http";
import { Server } from "socket.io";

import authRoutes from "./routes/auth.routes.js";
import protectedRoutes from "./routes/protected.routes.js";
import adminRoutes from "./routes/admin.routes.js";
import fileRoutes from "./routes/file.routes.js";

const app = express();

/* ================================
   🔐 TRUST PROXY (Required for Render)
================================ */
app.set("trust proxy", 1);

/* ================================
   🔐 SECURITY MIDDLEWARE
================================ */
app.use(helmet());
app.use(morgan("dev"));

/* ================================
   🌍 CORS CONFIG (IMPORTANT FIX)
================================ */
const allowedOrigins = [
  "http://localhost:5173",
  "https://secure-vault-s2pw.onrender.com", // your frontend URL
];

app.use(
  cors({
    origin: function (origin, callback) {

      // allow requests with no origin (mobile apps, curl, etc.)
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.log("Blocked by CORS:", origin);
        callback(new Error("CORS not allowed"));
      }
    },
    credentials: true,
  })
);

/* ================================
   📦 BODY PARSER
================================ */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ================================
   🚀 API ROUTES
================================ */
app.use("/api/auth", authRoutes);
app.use("/api/protected", protectedRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/files", fileRoutes);

/* ================================
   🟢 HEALTH CHECK ROUTE (IMPORTANT)
================================ */
app.get("/", (req, res) => {
  res.send("Secure Vault Backend is running ✅");
});

/* ================================
   ❌ 404 HANDLER
================================ */
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

/* ================================
   🛑 GLOBAL ERROR HANDLER
================================ */
app.use((err, req, res, next) => {
  console.error("Global error:", err.message);
  res.status(500).json({ message: err.message || "Internal server error" });
});

/* ================================
   🛑 MULTER ERROR HANDLER
================================ */
app.use((err, req, res, next) => {

  if (err.code === "LIMIT_FILE_SIZE") {

    return res.status(400).json({
      message: "File exceeds 50MB limit"
    });
  }

  console.error("Global error:", err.message);

  res.status(500).json({
    message: err.message
  });
});


/* ================================
   🔌 SOCKET.IO SETUP (FIXED)
================================ */
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true,
  },
});

// make io available everywhere
app.set("io", io);

io.on("connection", (socket) => {

  console.log("🔌 Admin connected:", socket.id);

  socket.on("disconnect", () => {
    console.log("❌ Admin disconnected:", socket.id);
  });

});

/* ================================
   🟢 START SERVER (FIXED FOR RENDER)
================================ */
const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {

  console.log("=================================");
  console.log(`🚀 Secure Vault Backend running`);
  console.log(`🌐 Port: ${PORT}`);
  console.log("=================================");

});

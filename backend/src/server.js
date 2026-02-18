import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import http from "http";
import { Server } from "socket.io";
import fs from "fs";
import path from "path";

/* ================================
   ROUTES
================================ */
import authRoutes from "./routes/auth.routes.js";
import protectedRoutes from "./routes/protected.routes.js";
import adminRoutes from "./routes/admin.routes.js";
import fileRoutes from "./routes/file.routes.js";

/* ================================
   INIT APP
================================ */
const app = express();


/* ================================
   TRUST PROXY (Required for Render)
================================ */
app.set("trust proxy", 1);


/* ================================
   ENSURE REQUIRED DIRECTORIES
================================ */

const REQUIRED_DIRS = [

  "vault",
  "quarantine",
  "temp"

];

REQUIRED_DIRS.forEach(dir => {

  if (!fs.existsSync(dir)) {

    fs.mkdirSync(dir, { recursive: true });

    console.log(`Created directory: ${dir}`);

  }

});


/* ================================
   SECURITY MIDDLEWARE
================================ */

app.use(helmet());

app.use(morgan("dev"));


/* ================================
   CORS CONFIG
================================ */

const allowedOrigins = [

  "http://localhost:5173",

  "https://secure-vault-s2pw.onrender.com"

];

app.use(cors({

  origin: function(origin, callback) {

    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {

      callback(null, true);

    }
    else {

      console.log("Blocked by CORS:", origin);

      callback(new Error("CORS not allowed"));

    }

  },

  credentials: true

}));


/* ================================
   BODY PARSER
================================ */

app.use(express.json({
  limit: "50mb"
}));

app.use(express.urlencoded({
  extended: true,
  limit: "50mb"
}));


/* ================================
   SOCKET SERVER
================================ */

const server = http.createServer(app);

const io = new Server(server, {

  cors: {

    origin: allowedOrigins,

    methods: ["GET", "POST"],

    credentials: true

  }

});

// make io accessible everywhere
app.set("io", io);


io.on("connection", (socket) => {

  console.log("🔌 Admin connected:", socket.id);

  socket.on("disconnect", () => {

    console.log("❌ Admin disconnected:", socket.id);

  });

});


/* ================================
   API ROUTES
================================ */

app.use("/api/auth", authRoutes);

app.use("/api/protected", protectedRoutes);

app.use("/api/admin", adminRoutes);

app.use("/api/files", fileRoutes);


/* ================================
   HEALTH CHECK
================================ */

app.get("/", (req, res) => {

  res.json({

    status: "OK",

    service: "SecureVault Backend",

    encryption: "AES-256-GCM",

    malwareProtection: "VirusTotal + SHA256",

    quarantine: true

  });

});


/* ================================
   MULTER ERROR HANDLER
================================ */

app.use((err, req, res, next) => {

  if (err.code === "LIMIT_FILE_SIZE") {

    return res.status(400).json({

      message: "File exceeds 32MB upload limit"

    });

  }

  next(err);

});


/* ================================
   GLOBAL ERROR HANDLER
================================ */

app.use((err, req, res, next) => {

  console.error("Global error:", err);

  res.status(500).json({

    message: err.message || "Internal server error"

  });

});


/* ================================
   404 HANDLER
================================ */

app.use((req, res) => {

  res.status(404).json({

    message: "Route not found"

  });

});


/* ================================
   START SERVER
================================ */

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {

  console.log("=================================");
  console.log("🚀 SecureVault Enterprise Backend");
  console.log(`🌐 Running on port ${PORT}`);
  console.log("🔐 AES-256-GCM Encryption enabled");
  console.log("🦠 AI Malware Detection enabled");
  console.log("📦 Quarantine system enabled");
  console.log("=================================");

});

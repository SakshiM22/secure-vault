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
   🔐 TRUST PROXY
   ================================ */
app.set("trust proxy", true);

/* ================================
   🔐 SECURITY MIDDLEWARE
   ================================ */
app.use(helmet());
app.use(morgan("dev"));

/* ================================
   🌍 CORS CONFIG
   ================================ */
const allowedOrigins = [
  "http://localhost:5173",
  process.env.FRONTEND_URL,
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
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
   🚀 ROUTES
   ================================ */
app.use("/api/auth", authRoutes);
app.use("/api/protected", protectedRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/files", fileRoutes);

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
  res.status(500).json({ message: "Internal server error" });
});

/* ================================
   🔌 SOCKET.IO SETUP
   ================================ */
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    credentials: true,
  },
});

// Make io accessible in routes
app.set("io", io);

io.on("connection", (socket) => {
  console.log("🔌 Admin connected:", socket.id);

  socket.on("disconnect", () => {
    console.log("❌ Admin disconnected:", socket.id);
  });
});

/* ================================
   🟢 START SERVER
   ================================ */
const PORT = process.env.PORT || 5000;

server.listen(PORT, () =>
  console.log(`🚀 Backend running on http://localhost:${PORT}`)
);

import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/axios";
import { useAuth } from "../context/AuthContext";
import "../styles/userDashboard.css";

function UserDashboard() {
  const navigate = useNavigate();
  const { logout, user } = useAuth();

  const [stats, setStats] = useState({
    totalFiles: 0,
    totalSize: 0,
    recentActivity: [],
  });

  useEffect(() => {
    fetchDashboardData();
  }, []);

  /* ===============================
     FORMAT STORAGE SIZE
  =============================== */
  const formatSize = (bytes) => {
    if (!bytes || bytes === 0) return "0 B";

    const KB = 1024;
    const MB = KB * 1024;
    const GB = MB * 1024;

    if (bytes < KB) return bytes + " B";
    if (bytes < MB) return (bytes / KB).toFixed(2) + " KB";
    if (bytes < GB) return (bytes / MB).toFixed(2) + " MB";

    return (bytes / GB).toFixed(2) + " GB";
  };

  /* ===============================
     FETCH DASHBOARD DATA
  =============================== */
  const fetchDashboardData = async () => {
    try {
      const filesRes = await api.get("/files/my-files");

      const files = filesRes.data || [];

      // 🔥 CRITICAL FIX: ensure number conversion
      const totalSize = files.reduce(
        (sum, file) => sum + Number(file.file_size || 0),
        0
      );

      setStats({
        totalFiles: files.length,
        totalSize: totalSize,
        recentActivity: files.slice(0, 5),
      });

    } catch (error) {
      console.error("Dashboard fetch error:", error);
    }
  };

  /* ===============================
     LOGOUT
  =============================== */
  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="dashboard-container">

      <h1>👋 Welcome, {user?.email}</h1>

      <p className="subtitle">
        This is your secure vault dashboard.
      </p>

      {/* ===============================
         STATS CARDS
      =============================== */}
      <div className="stats-grid">

        <div className="card">
          <h3>Total Stored Files</h3>
          <p>{stats.totalFiles}</p>
        </div>

        <div className="card">
          <h3>Total Storage Used</h3>
          <p>{formatSize(stats.totalSize)}</p>
        </div>

        <div className="card">
          <h3>Account Status</h3>
          <p className="active-status">Active</p>
        </div>

      </div>

      {/* ===============================
         ACTION BUTTONS
      =============================== */}
      <div className="actions">

        <button onClick={() => navigate("/upload")}>
          🔐 Upload File
        </button>

        <button onClick={() => navigate("/my-files")}>
          📂 My Files
        </button>

        <button className="logout" onClick={handleLogout}>
          🚪 Logout
        </button>

      </div>

      {/* ===============================
         RECENT ACTIVITY
      =============================== */}
      <div className="recent-section">

        <h2>🕒 Recent Uploads</h2>

        {stats.recentActivity.length === 0 ? (

          <p>No recent uploads.</p>

        ) : (

          <ul>
            {stats.recentActivity.map((file) => (
              <li key={file.id}>
                {file.original_name} —{" "}
                {new Date(file.created_at).toLocaleString()}
              </li>
            ))}
          </ul>

        )}

      </div>

    </div>
  );
}

export default UserDashboard;

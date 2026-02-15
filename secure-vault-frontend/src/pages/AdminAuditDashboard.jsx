import { useEffect, useState } from "react";
import api from "../api/axios";
import AdminSidebar from "../components/admin/AdminSidebar";
import { io } from "socket.io-client";
import "../styles/adminDashboard.css";

const socket = io(import.meta.env.VITE_API_URL, {
  withCredentials: true,
});

function AdminAuditDashboard() {

  const [logs, setLogs] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [suspicious, setSuspicious] = useState(null);
  const [users, setUsers] = useState([]);
  const [malwareFiles, setMalwareFiles] = useState([]); // NEW
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  /* ==============================
     INITIAL LOAD
  ============================== */

  useEffect(() => {

    fetchAll();

    socket.on("audit:new", (newLog) => {

      setLogs(prev => [newLog, ...prev]);

      fetchAnalytics();
      fetchMalwareFiles();

    });

    return () => socket.off("audit:new");

  }, []);

  /* ==============================
     FETCH ALL ADMIN DATA
  ============================== */

  const fetchAll = async () => {

    try {

      const [
        logsRes,
        analyticsRes,
        suspiciousRes,
        usersRes,
        malwareRes
      ] = await Promise.all([

        api.get("/admin/audit-logs"),
        api.get("/admin/analytics"),
        api.get("/admin/suspicious-activity"),
        api.get("/admin/users"),
        api.get("/admin/malware-files") // NEW

      ]);

      setLogs(logsRes.data);
      setAnalytics(analyticsRes.data);
      setSuspicious(suspiciousRes.data);
      setUsers(usersRes.data);
      setMalwareFiles(malwareRes.data);

    } catch (error) {

      console.error("Admin fetch error:", error);

    } finally {

      setLoading(false);

    }
  };

  const fetchAnalytics = async () => {

    try {

      const res = await api.get("/admin/analytics");
      setAnalytics(res.data);

    } catch {

      console.error("Analytics refresh failed");

    }
  };

  const fetchMalwareFiles = async () => {

    try {

      const res = await api.get("/admin/malware-files");

      setMalwareFiles(res.data);

    } catch {

      console.error("Malware fetch failed");

    }
  };

  /* ==============================
     USER ACTIONS
  ============================== */

  const lockUser = async (id) => {
    await api.patch(`/admin/users/${id}/lock`);
    fetchAll();
  };

  const unlockUser = async (id) => {
    await api.patch(`/admin/users/${id}/unlock`);
    fetchAll();
  };

  const promoteUser = async (id) => {
    await api.patch(`/admin/users/${id}/promote`);
    fetchAll();
  };

  const demoteUser = async (id) => {
    await api.patch(`/admin/users/${id}/demote`);
    fetchAll();
  };

  const deleteUser = async (id) => {

    if (!window.confirm("Delete this user permanently?"))
      return;

    await api.delete(`/admin/users/${id}`);

    fetchAll();
  };

  /* ==============================
     FILTER LOGS
  ============================== */

  const filteredLogs = logs.filter(log =>
    log.user_email?.toLowerCase().includes(search.toLowerCase()) ||
    log.ip_address?.includes(search)
  );

  return (

    <div className="admin-layout">

      <AdminSidebar />

      <div className="admin-content">

        <h1 className="dashboard-title">
          🛡️ Security Control Center
        </h1>

        {/* =====================
           ANALYTICS
        ===================== */}

        {!loading && analytics && (

          <div className="analytics-grid">

            <AnalyticsCard title="Total Users" value={analytics.totalUsers} />

            <AnalyticsCard
              title="Locked Accounts"
              value={analytics.lockedAccounts}
              danger={analytics.lockedAccounts > 0}
            />

            <AnalyticsCard
              title="Failed Logins (24h)"
              value={analytics.failedLogins24h}
              danger={analytics.failedLogins24h > 10}
            />

            <AnalyticsCard title="Uploads" value={analytics.totalUploads} />

            <AnalyticsCard title="Downloads" value={analytics.totalDownloads} />

            {/* NEW MALWARE CARD */}

            <AnalyticsCard
              title="Malware Detected Files"
              value={malwareFiles.length}
              danger={malwareFiles.length > 0}
            />

          </div>

        )}

        {/* =====================
           MALWARE FILES SECTION
        ===================== */}

        <h2 className="section-title">
          🦠 Malware Detected Files
        </h2>

        <div className="table-wrapper">

          <table className="audit-table">

            <thead>

              <tr>

                <th>File Name</th>
                <th>User ID</th>
                <th>Malicious Engines</th>
                <th>Status</th>
                <th>Time</th>

              </tr>

            </thead>

            <tbody>

              {malwareFiles.length === 0 ? (

                <tr>
                  <td colSpan="5">No malware detected</td>
                </tr>

              ) : (

                malwareFiles.map(file => (

                  <tr key={file.id} className="danger-row">

                    <td>{file.original_name}</td>

                    <td>{file.user_id}</td>

                    <td>{file.malicious_count}</td>

                    <td>
                      <span className="danger-badge">
                        MALICIOUS
                      </span>
                    </td>

                    <td>
                      {new Date(file.created_at).toLocaleString()}
                    </td>

                  </tr>

                ))

              )}

            </tbody>

          </table>

        </div>

        {/* =====================
           USER MANAGEMENT
        ===================== */}

        <h2 className="section-title">
          👥 User Management
        </h2>

        <div className="table-wrapper">

          <table className="audit-table">

            <thead>

              <tr>

                <th>Email</th>
                <th>Role</th>
                <th>Locked</th>
                <th>Failed Attempts</th>
                <th>Actions</th>

              </tr>

            </thead>

            <tbody>

              {users.map(user => (

                <tr key={user.id}>

                  <td>{user.email}</td>

                  <td>{user.role}</td>

                  <td>{user.is_locked ? "Yes" : "No"}</td>

                  <td>{user.failed_attempts}</td>

                  <td>

                    {user.is_locked ? (

                      <button onClick={() => unlockUser(user.id)}>
                        Unlock
                      </button>

                    ) : (

                      <button onClick={() => lockUser(user.id)}>
                        Lock
                      </button>

                    )}

                    <button onClick={() => deleteUser(user.id)}>
                      Delete
                    </button>

                  </td>

                </tr>

              ))}

            </tbody>

          </table>

        </div>

        {/* =====================
           AUDIT LOGS
        ===================== */}

        <h2 className="section-title">
          🧾 Audit Logs
        </h2>

        <input
          type="text"
          placeholder="Search..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />

        <div className="table-wrapper">

          <table className="audit-table">

            <thead>

              <tr>

                <th>Email</th>
                <th>Action</th>
                <th>Status</th>
                <th>IP</th>
                <th>Time</th>

              </tr>

            </thead>

            <tbody>

              {filteredLogs.map(log => (

                <tr key={log.id}>

                  <td>{log.user_email}</td>
                  <td>{log.action}</td>
                  <td>{log.status}</td>
                  <td>{log.ip_address}</td>
                  <td>
                    {new Date(log.created_at).toLocaleString()}
                  </td>

                </tr>

              ))}

            </tbody>

          </table>

        </div>

      </div>

    </div>

  );
}

/* ===================== */

function AnalyticsCard({ title, value, danger }) {

  return (

    <div className={`analytics-card ${danger ? "danger" : ""}`}>

      <h4>{title}</h4>

      <p>{value}</p>

    </div>

  );
}

export default AdminAuditDashboard;

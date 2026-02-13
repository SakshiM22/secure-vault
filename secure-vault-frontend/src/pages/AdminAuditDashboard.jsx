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
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  /* ==============================
     INITIAL LOAD
  ============================== */
  useEffect(() => {
    fetchAll();

    socket.on("audit:new", (newLog) => {
      setLogs((prev) => [newLog, ...prev]);
      fetchAnalytics();
    });

    return () => socket.off("audit:new");
  }, []);

  /* ==============================
     FETCH ALL ADMIN DATA
  ============================== */
  const fetchAll = async () => {
    try {
      const [logsRes, analyticsRes, suspiciousRes, usersRes] =
        await Promise.all([
          api.get("/admin/audit-logs"),
          api.get("/admin/analytics"),
          api.get("/admin/suspicious-activity"),
          api.get("/admin/users"),
        ]);

      setLogs(logsRes.data);
      setAnalytics(analyticsRes.data);
      setSuspicious(suspiciousRes.data);
      setUsers(usersRes.data);
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

  /* ==============================
     USER ACTION HANDLERS
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

const forceLogout = async (id) => {
  await api.patch(`/admin/users/${id}/force-logout`);
  alert("User session invalidated.");
};

const deleteUser = async (id) => {
  if (!window.confirm("Delete this user permanently?")) return;
  await api.delete(`/admin/users/${id}`);
  fetchAll();
};

  /* ==============================
     FILTER LOGS
  ============================== */
  const filteredLogs = logs.filter((log) =>
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

        {/* ===========================
           ANALYTICS
        ============================ */}
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
            <AnalyticsCard
              title="Locks (24h)"
              value={analytics.locks24h}
              danger={analytics.locks24h > 0}
            />
          </div>
        )}

        {/* ===========================
           SUSPICIOUS ACTIVITY
        ============================ */}
        <h2 className="section-title">🚨 Suspicious Activity</h2>

        {suspicious && (
          <div className="suspicious-grid">
            <SuspiciousBlock
              title="Excessive Failed Logins"
              data={suspicious.failedLoginUsers || []}
            />
            <SuspiciousBlock
              title="Suspicious IPs"
              data={suspicious.suspiciousIPs || []}
            />
            <SuspiciousBlock
              title="Recent Account Locks"
              data={suspicious.recentLocks || []}
            />
            <SuspiciousBlock
              title="High Upload Rate"
              data={suspicious.highUploadUsers || []}
            />
          </div>
        )}

        {/* ===========================
           USER MANAGEMENT
        ============================ */}
        <h2 className="section-title">👥 User Management</h2>

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
              {users.map((user) => (
                <tr key={user.id}>
                  <td>{user.email}</td>
                  <td>{user.role}</td>
                  <td>{user.is_locked ? "Yes" : "No"}</td>
                  <td>{user.failed_attempts}</td>
                  <td className="action-buttons">

                    {user.is_locked ? (
                      <button onClick={() => unlockUser(user.id)}>
                        Unlock
                      </button>
                    ) : (
                      <button onClick={() => lockUser(user.id)}>
                        Lock
                      </button>
                    )}

                    {user.role === "user" ? (
                      <button onClick={() => promoteUser(user.id)}>
                        Promote
                      </button>
                    ) : (
                      <button onClick={() => demoteUser(user.id)}>
                        Demote
                      </button>
                    )}

                    {/* <button onClick={() => forceLogout(user.id)}>
                      Force Logout
                    </button> */}

                    <button
                      className="danger-btn"
                      onClick={() => deleteUser(user.id)}
                    >
                      Delete
                    </button>

                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* ===========================
           AUDIT LOGS
        ============================ */}
        <h2 className="section-title">🧾 Audit Logs</h2>

        <div className="filter-bar">
          <input
            type="text"
            placeholder="Search email or IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="search-input"
          />
        </div>

        {!loading && (
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
                {filteredLogs.map((log) => (
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
        )}
      </div>
    </div>
  );
}

/* ===========================
   SUB COMPONENTS
=========================== */

function AnalyticsCard({ title, value, danger }) {
  return (
    <div className={`analytics-card ${danger ? "danger" : ""}`}>
      <h4>{title}</h4>
      <p>{value}</p>
    </div>
  );
}

function SuspiciousBlock({ title, data }) {
  return (
    <div className={`suspicious-card ${data.length > 0 ? "danger" : ""}`}>
      <h4>{title}</h4>
      {data.length === 0 ? (
        <p>✅ No issues detected</p>
      ) : (
        <ul>
          {data.map((item, index) => (
            <li key={index}>
              {Object.values(item).join(" | ")}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default AdminAuditDashboard;

import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import "../../styles/adminSidebar.css";

function AdminSidebar() {
  const navigate = useNavigate();
  const { logout, user } = useAuth();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="admin-sidebar">
      
      {/* Top Section */}
      <div>
        <div className="admin-header">
          <h2>🔐 Admin Panel</h2>
          <button className="logout-btn" onClick={handleLogout}>
            🚪 Logout
          </button>
        </div>

        <div className="admin-user-info">
          <span>Logged in as an Admin</span>
          <strong>{user?.email}</strong>
        </div>

        <div className="admin-nav">
          <button
            onClick={() => navigate("/admin/audit-logs")}
            className="nav-btn"
          >
            📊 Dashboard
          </button>
        </div>
      </div>

      {/* Footer */}
      <div className="admin-footer">
        Secure Vault System © 2026
      </div>
    </div>
  );
}

export default AdminSidebar;

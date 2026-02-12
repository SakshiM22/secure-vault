import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { loginUser } from "../../api/authApi";
import "../../styles/auth.css";

function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [attempts, setAttempts] = useState(0);

  const { login } = useAuth();
  const navigate = useNavigate();

  const MAX_ATTEMPTS = 3;

  const handleLogin = async (e) => {
    e.preventDefault();

    // Basic validation
    if (!email || !password) {
      handleFailedAttempt();
      return;
    }

    try {
      setLoading(true);
      setError("");

      // 🔐 Call backend login API
      const data = await loginUser(email, password);

      // ✅ Store token + full user object
      login(data.token, data.user);

      // ✅ ROLE-BASED REDIRECT
      if (data.user.role === "admin") {
        navigate("/admin/audit-logs");
      } else {
        navigate("/dashboard");
      }
    } catch (err) {
      // 🔒 Account locked (backend-enforced)
      if (err.response?.status === 423) {
        navigate("/account-locked");
        return;
      }

      // ❌ Invalid credentials
      handleFailedAttempt();
    } finally {
      setLoading(false);
    }
  };

  const handleFailedAttempt = () => {
    const newAttempts = attempts + 1;
    setAttempts(newAttempts);
    setError("Invalid credentials");

    // Frontend UX lock (backend is authority)
    if (newAttempts >= MAX_ATTEMPTS) {
      navigate("/account-locked");
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-box">
        <h2>Secure Login</h2>

        {error && <div className="error-text">{error}</div>}

        {attempts > 0 && attempts < MAX_ATTEMPTS && (
          <div
            style={{
              fontSize: "13px",
              color: "#f59e0b",
              marginBottom: "10px",
            }}
          >
            Warning: {MAX_ATTEMPTS - attempts} attempt(s) remaining
          </div>
        )}

        <label>Email</label>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="username"
        />

        <label>Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
        />

        <button
          className="btn btn-primary"
          style={{ width: "100%" }}
          onClick={handleLogin}
          disabled={loading}
        >
          {loading ? "Authenticating..." : "Login"}
        </button>

        <div className="auth-footer">
          Don’t have an account? <a href="/signup">Sign up</a>
        </div>
      </div>
    </div>
  );
}

export default Login;

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { signupUser } from "../../api/authApi";
import { checkPasswordStrength } from "../../utils/passwordStrength";
import "../../styles/auth.css";

function Signup() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const navigate = useNavigate();

  // SAFE: always pass a string
  const strength = checkPasswordStrength(password || "");

  const handleSignup = async (e) => {
    e.preventDefault();

    // Re-check strength at submit time (defensive)
    const currentStrength = checkPasswordStrength(password || "");

    if (!email || !password || !confirm) {
      setError("All fields are required");
      return;
    }

    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }

    if (currentStrength.label === "Weak") {
      setError("Password is too weak");
      return;
    }

    try {
      setLoading(true);
      setError("");

      await signupUser(email, password);

      // Redirect to login after successful signup
      navigate("/login");
    } catch (err) {
      if (err.response?.status === 409) {
        setError("Account already exists");
      } else {
        setError("Signup failed");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-box">
        <h2>Create Secure Account</h2>

        {error && <div className="error-text">{error}</div>}

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
          autoComplete="new-password"
        />

        {password && (
          <div className={`strength ${strength.color}`}>
            Password strength: {strength.label}
          </div>
        )}

        <label>Confirm Password</label>
        <input
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
        />

        <button
          className="btn btn-primary"
          style={{ width: "100%" }}
          onClick={handleSignup}
          disabled={loading}
        >
          {loading ? "Creating account..." : "Sign Up"}
        </button>

        <div className="auth-footer">
          Already have an account? <a href="/login">Login</a>
        </div>
      </div>
    </div>
  );
}

export default Signup;

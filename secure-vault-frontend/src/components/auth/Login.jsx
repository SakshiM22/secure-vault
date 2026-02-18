import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { loginUser } from "../../api/authApi";
import "../../styles/auth.css";

function Login() {

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("user");

  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [attempts, setAttempts] = useState(0);

  const navigate = useNavigate();
  const { login } = useAuth();

  const MAX_ATTEMPTS = 3;


  /* =====================================
     LOGIN HANDLER
  ===================================== */

  const handleLogin = async (e) => {

    e.preventDefault();

    if (!email || !password || !role) {

      setError("All fields required");
      return;

    }

    try {

      setLoading(true);
      setError("");

      const data =
        await loginUser(
          email,
          password,
          role
        );


      /* STORE AUTH DATA */

      login(
        data.token,
        data.user
      );


      /* ROLE BASED REDIRECT */

      if (data.user.role === "admin") {

        navigate("/admin/audit-logs");

      }
      else {

        navigate("/dashboard");

      }

    }
    catch (err) {

      console.error(err);

      if (err.response?.status === 423) {

        navigate("/account-locked");
        return;

      }

      if (err.response?.status === 403) {

        setError("Access denied: wrong role selected");
        return;

      }

      const newAttempts =
        attempts + 1;

      setAttempts(newAttempts);

      setError("Invalid credentials");

      if (newAttempts >= MAX_ATTEMPTS) {

        navigate("/account-locked");

      }

    }
    finally {

      setLoading(false);

    }

  };


  /* =====================================
     UI
  ===================================== */

  return (

    <div className="auth-container">

      <div className="auth-box">

        <h2>Secure Vault Login</h2>


        {error &&
          <div className="error-text">
            {error}
          </div>
        }


        {/* EMAIL */}

        <label>Email</label>

        <input
          type="email"
          value={email}
          onChange={(e)=>
            setEmail(e.target.value)
          }
        />


        {/* PASSWORD */}

        <label>Password</label>

        <input
          type="password"
          value={password}
          onChange={(e)=>
            setPassword(e.target.value)
          }
        />


        {/* ROLE SELECT */}

        <label>Login as</label>

        <select
          value={role}
          onChange={(e)=>
            setRole(e.target.value)
          }
          className="role-select"
        >

          <option value="user">
            User
          </option>

          <option value="admin">
            Admin
          </option>

        </select>


        {/* BUTTON */}

        <button
          onClick={handleLogin}
          disabled={loading}
          className="btn btn-primary"
          style={{ width: "100%" }}
        >

          {loading
            ? "Authenticating..."
            : "Login"
          }

        </button>


        <div className="auth-footer">

          Don’t have an account?

          <a href="/signup">
            Sign up
          </a>

        </div>

      </div>

    </div>

  );

}

export default Login;

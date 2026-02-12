import "../../styles/auth.css";

function AccountLocked() {
  return (
    <div className="auth-container">
      <div className="auth-box">
        <h2 style={{ color: "#ef4444" }}>Account Locked</h2>

        <p style={{ marginBottom: "15px", fontSize: "14px" }}>
          Your account has been temporarily locked due to multiple failed login
          attempts.
        </p>

        <p style={{ fontSize: "13px", color: "#94a3b8" }}>
          Please try again after some time or contact the administrator if the
          issue persists.
        </p>

        <div className="auth-footer" style={{ marginTop: "20px" }}>
          <a href="/login">Back to Login</a>
        </div>
      </div>
    </div>
  );
}

export default AccountLocked;

import { useNavigate } from "react-router-dom";
import "../styles/home.css";

function Home() {

  const navigate = useNavigate();

  return (

    <div className="home-container">

      {/* NAVBAR */}
      <nav className="home-navbar">

        <div className="logo">
          🔐 SecureVault
        </div>

        <div className="nav-buttons">

          <button
            className="nav-btn"
            onClick={() => navigate("/login")}
          >
            Login
          </button>

          <button
            className="nav-btn primary"
            onClick={() => navigate("/signup")}
          >
            Get Started
          </button>

        </div>

      </nav>


      {/* HERO */}
      <section className="hero-section">

        <div className="hero-left">

          <h1>
            Secure Access Controlled Vault
          </h1>

          <p>
            Encrypt, store, and monitor your files with security,
            threat detection, and real-time admin analytics.
          </p>

          <div className="hero-buttons">

            <button
              className="primary-btn"
              onClick={() => navigate("/login")}
            >
              Store File
            </button>

            <button
              className="secondary-btn"
              onClick={() => navigate("/login")}
            >
              Open Dashboard
            </button>

          </div>

        </div>

        <div className="hero-right">

          <div className="vault-animation">
            🔐
          </div>

        </div>

      </section>


      {/* FEATURES */}
      <section className="features-section">

        <h2>Security Features</h2>

        <div className="features-grid">

          <FeatureCard
            icon="🔐"
            title="User-specific File Access"
            desc="Restricts files access only to file owners"
          />

          <FeatureCard
            icon="🛡️"
            title="Threat Detection"
            desc="Detect suspicious login and attack attempts instantly"
          />

          <FeatureCard
            icon="📊"
            title="Admin Security Analytics"
            desc="Monitor uploads, downloads, and security events"
          />

          <FeatureCard
            icon="🚫"
            title="Unauthorized Access Protection"
            desc="Automatic account lock and session invalidation"
          />

        </div>

      </section>


      {/* CTA */}
      <section className="cta-section">

        <h2>Protect Your Files Today</h2>

        <button
          className="primary-btn large"
          onClick={() => navigate("/signup")}
        >
          Create Secure Account
        </button>

      </section>


      {/* FOOTER */}
      <footer className="home-footer">
        © 2026 SecureVault • All Rights Reserved
      </footer>

    </div>
  );

}


function FeatureCard({ icon, title, desc }) {

  return (

    <div className="feature-card">

      <div className="feature-icon">
        {icon}
      </div>

      <h3>{title}</h3>

      <p>{desc}</p>

    </div>

  );

}

export default Home;

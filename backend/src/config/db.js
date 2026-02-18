import pkg from "pg";
const { Pool } = pkg;

/* =========================================
   DATABASE CONFIGURATION
========================================= */

const pool = new Pool({

  connectionString: process.env.DATABASE_URL,

  ssl: {
    rejectUnauthorized: false, // required for Render PostgreSQL
  },

  /* =========================================
     CONNECTION POOL SETTINGS (Production)
  ========================================= */

  max: 20, // maximum concurrent connections

  idleTimeoutMillis: 30000, // close idle connections after 30s

  connectionTimeoutMillis: 10000, // fail if cannot connect in 10s

});


/* =========================================
   CONNECTION SUCCESS TEST
========================================= */

(async () => {

  try {

    const client = await pool.connect();

    console.log("=================================");
    console.log("PostgreSQL connected successfully ✅");
    console.log("Database ready for SecureVault 🔐");
    console.log("=================================");

    client.release();

  } catch (err) {

    console.error("=================================");
    console.error("PostgreSQL connection FAILED ❌");
    console.error(err.message);
    console.error("=================================");

    process.exit(1); // stop server if DB fails
  }

})();


/* =========================================
   GLOBAL ERROR HANDLER
========================================= */

pool.on("error", (err) => {

  console.error("Unexpected PostgreSQL error:", err.message);

});


/* =========================================
   SAFE QUERY FUNCTION (OPTIONAL)
   prevents crashes
========================================= */

export const safeQuery = async (text, params) => {

  try {

    const res = await pool.query(text, params);

    return res;

  } catch (error) {

    console.error("Database query error:", error.message);

    throw error;

  }

};


export default pool;

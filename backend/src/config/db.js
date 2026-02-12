import pkg from "pg";
const { Pool } = pkg;

const pool = new Pool({
  user: "postgres",          // change if different
  host: "localhost",
  database: "secure_vault",  // your DB name
  password: "newpassword123", // postgres password
  port: 5432,
});

// 🔴 FORCE CONNECTION TEST
(async () => {
  try {
    const client = await pool.connect();
    console.log("PostgreSQL connected successfully");
    client.release();
  } catch (err) {
    console.error("PostgreSQL connection FAILED ❌");
    console.error(err.message);
  }
})();

export default pool;

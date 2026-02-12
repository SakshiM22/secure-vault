import pkg from "pg";
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,

  ssl: {
    rejectUnauthorized: false,
  },
});

// 🔴 FORCE CONNECTION TEST
(async () => {
  try {
    const client = await pool.connect();
    console.log("PostgreSQL connected successfully ✅");
    client.release();
  } catch (err) {
    console.error("PostgreSQL connection FAILED ❌");
    console.error(err.message);
  }
})();

export default pool;

require("dotenv").config();
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function resetAdminPassword() {
  try {
    const email = "abubakarmubarak3456@gmail.com"; // admin email
    const newPassword = "Admin1234!"; // choose a secure password
    const hashed = await bcrypt.hash(newPassword, 10);

    const res = await pool.query(
      "UPDATE users SET password=$1 WHERE email=$2 RETURNING id, name",
      [hashed, email]
    );

    if (res.rowCount === 0) {
      console.log("Admin email not found in database!");
    } else {
      console.log(`✅ Password reset for ${res.rows[0].name} (${email})`);
      console.log(`New password: ${newPassword}`);
    }
  } catch (err) {
    console.error("Error resetting admin password:", err);
  } finally {
    await pool.end();
  }
}

resetAdminPassword();

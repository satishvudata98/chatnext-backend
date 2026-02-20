import postgres from "postgres";
import dotenv from "dotenv";

dotenv.config();

console.log("Connecting to Supabase Pooler via IPv4...");

const sql = postgres(process.env.DATABASE_URL, {
    ssl: "require",
    connect_timeout: 30,
    idle_timeout: 20,
    max: 10,
});

export default sql;
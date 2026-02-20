import supabase from './supabaseClient.js';

console.log("Testing Supabase connection...");

try {

    const { data, error } = await supabase
        .from('users')
        .select('*')
        .limit(1);

    if (error)
        console.error("FAILED:", error);
    else
        console.log("SUCCESS:", data);

} catch (err) {

    console.error("ERROR:", err);

}

process.exit();
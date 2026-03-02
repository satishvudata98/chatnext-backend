import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

function decodeJwtPayload(jwt) {
  try {
    const parts = jwt.split('.');
    if (parts.length < 2) return null;
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceRoleKey) {
  throw new Error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in backend .env');
}

if (supabaseServiceRoleKey.startsWith('sb_publishable_')) {
  throw new Error(
    'SUPABASE_SERVICE_ROLE_KEY is set to a publishable key (sb_publishable_*). ' +
      'Use the Service Role key from Supabase Project Settings > API.'
  );
}

const decodedPayload = decodeJwtPayload(supabaseServiceRoleKey);
if (decodedPayload?.role && decodedPayload.role !== 'service_role') {
  throw new Error(
    `SUPABASE_SERVICE_ROLE_KEY is not a service role key (detected role: ${decodedPayload.role}). ` +
      'Use the Service Role key from Supabase Project Settings > API.'
  );
}

const supabase = createClient(
    supabaseUrl,
    supabaseServiceRoleKey,
    {
        auth: {
            persistSession: false
        }
    }
);

export default supabase;

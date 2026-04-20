import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "https://ztlhmdxlneavnubgnhtu.supabase.co";
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "sb_publishable_eqa_gHHDmAzCSqRq1WAyeA_MAm42zMw";

export const supabase = createClient(supabaseUrl, supabaseKey);

import { createClient } from "@supabase/supabase-js";
import { NextResponse } from "next/server";

const supabase = createClient(
  "https://ztlhmdxlneavnubgnhtu.supabase.co",
  "sb_publishable_eqa_gHHDmAzCSqRq1WAyeA_MAm42zMw"
);

export async function GET(
  request: Request,
  { params }: { params: Promise<{ token: string }> }
) {
  const { token } = await params;

  const { data: share } = await supabase
    .from("shares")
    .select("*, devices(tunnel_url, last_seen)")
    .eq("token", token)
    .eq("is_active", true)
    .single();

  if (!share) {
    return NextResponse.json({ online: false, downloadUrl: null });
  }

  const device = share.devices;
  const lastSeen = device?.last_seen ? new Date(device.last_seen) : null;
  const online = lastSeen !== null && (Date.now() - lastSeen.getTime()) < 60000;
  const downloadUrl = online && device?.tunnel_url
    ? `${device.tunnel_url}/${token}/file`
    : null;

  return NextResponse.json({ online, downloadUrl });
}

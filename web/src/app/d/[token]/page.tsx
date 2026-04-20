import { createClient } from "@supabase/supabase-js";
import { notFound } from "next/navigation";
import DownloadClient from "./download-client";

const supabase = createClient(
  "https://ztlhmdxlneavnubgnhtu.supabase.co",
  "sb_publishable_eqa_gHHDmAzCSqRq1WAyeA_MAm42zMw"
);

export const dynamic = "force-dynamic"; // Always fresh data

interface PageProps {
  params: Promise<{ token: string }>;
}

export default async function DownloadPage({ params }: PageProps) {
  const { token } = await params;

  // Look up the share with its device
  const { data: share, error } = await supabase
    .from("shares")
    .select("*, devices(tunnel_url, last_seen)")
    .eq("token", token)
    .eq("is_active", true)
    .single();

  if (error || !share) {
    notFound();
  }

  // Check if expired
  if (new Date(share.expires_at) < new Date()) {
    return (
      <main className="min-h-screen flex items-center justify-center px-6">
        <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-10 max-w-md w-full text-center">
          <div className="text-5xl font-bold text-zinc-700 mb-3">410</div>
          <p className="text-zinc-400">This share has expired</p>
          <p className="text-xs text-zinc-600 mt-6">Spize</p>
        </div>
      </main>
    );
  }

  const device = share.devices;
  const tunnelUrl = device?.tunnel_url || null;
  const lastSeen = device?.last_seen ? new Date(device.last_seen) : null;
  const isOnline = lastSeen !== null && (Date.now() - lastSeen.getTime()) < 60000;

  const downloadUrl = tunnelUrl ? `${tunnelUrl}/${token}/file` : null;

  return (
    <DownloadClient
      fileName={share.file_name}
      fileSize={share.file_size}
      isFolder={share.is_folder}
      hasPassword={share.has_password}
      isOnline={isOnline}
      downloadUrl={downloadUrl}
      token={token}
    />
  );
}

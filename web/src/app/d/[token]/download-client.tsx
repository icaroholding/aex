"use client";

import { useEffect, useState } from "react";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

interface Props {
  fileName: string;
  fileSize: number | null;
  isFolder: boolean;
  hasPassword: boolean;
  isOnline: boolean;
  downloadUrl: string | null;
  token: string;
}

export default function DownloadClient({
  fileName,
  fileSize,
  isFolder,
  hasPassword,
  isOnline: initialOnline,
  downloadUrl: initialUrl,
  token,
}: Props) {
  const [isOnline, setIsOnline] = useState(initialOnline);
  const [downloadUrl, setDownloadUrl] = useState(initialUrl);

  // Poll for online status every 15 seconds if offline
  useEffect(() => {
    if (isOnline) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/status/${token}`);
        const data = await res.json();
        if (data.online && data.downloadUrl) {
          setIsOnline(true);
          setDownloadUrl(data.downloadUrl);
        }
      } catch {
        // ignore fetch errors
      }
    }, 15000);

    return () => clearInterval(interval);
  }, [isOnline, token]);

  return (
    <main className="min-h-screen flex items-center justify-center px-6">
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-10 max-w-md w-full text-center">
        <div className="text-2xl font-bold mb-6">Spize</div>

        <div className="text-lg font-semibold mb-2 break-all">{fileName}</div>

        <div className="text-sm text-zinc-500 mb-6">
          {fileSize ? formatBytes(fileSize) : "Unknown size"}
          {isFolder ? " · Folder" : ""}
        </div>

        {isOnline && downloadUrl ? (
          <>
            <a
              href={downloadUrl}
              download
              className="block w-full py-3.5 bg-white text-zinc-900 rounded-xl font-semibold text-sm hover:bg-zinc-200 transition-colors"
            >
              Download
            </a>
            <div className="mt-3 inline-block bg-emerald-950 text-emerald-400 px-3 py-1 rounded-md text-xs">
              Online · Direct P2P · Resumable
            </div>
          </>
        ) : (
          <>
            <div className="block w-full py-3.5 bg-zinc-800 text-zinc-500 rounded-xl font-semibold text-sm cursor-not-allowed">
              Download
            </div>
            <div className="mt-3 inline-block bg-red-950 text-red-400 px-3 py-1 rounded-md text-xs">
              Sender offline
            </div>
            <p className="text-xs text-zinc-600 mt-4">
              The sender&apos;s device is currently offline.<br />
              This page will auto-retry every 15 seconds.
            </p>
          </>
        )}

        {hasPassword && (
          <p className="text-xs text-zinc-500 mt-4">🔒 Password protected</p>
        )}

        <p className="text-xs text-zinc-700 mt-8">
          Powered by Spize · Encrypted tunnel
        </p>
      </div>
    </main>
  );
}

export default function Home() {
  return (
    <main className="min-h-screen flex flex-col overflow-hidden">

      {/* ── Nav ── */}
      <nav className="relative z-10 flex items-center justify-between px-6 lg:px-16 py-5">
        <img src="/logo.svg" alt="Spize" className="h-[32px] lg:h-[39px]" />
        <div className="hidden md:flex items-center gap-6">
          <a href="#features" className="text-[15px] font-bold text-[#ebf0ff] hover:opacity-80 transition-opacity">Features</a>
          <a href="#how" className="text-[15px] font-bold text-[#ebf0ff] hover:opacity-80 transition-opacity">How it works</a>
          <a href="#faq" className="text-[15px] font-bold text-[#ebf0ff] hover:opacity-80 transition-opacity">FAQ</a>
        </div>
        <div className="flex items-center gap-2">
          <a href="#" className="px-4 py-2 text-[15px] font-bold text-[#c5d4ff] rounded-[11px] bg-[#1a3dbf]/37 hover:opacity-80 transition-opacity">Log in</a>
          <a href="#" className="px-4 py-2 text-[15px] font-bold text-[#e2eaff] rounded-[11px] bg-[#2c64ff] hover:opacity-90 transition-opacity">Sign up</a>
        </div>
      </nav>

      {/* ── Hero ── */}
      <section className="relative flex flex-col items-center text-center px-6 pt-10 lg:pt-16 pb-40 lg:pb-56">
        {/* Decorative horizontal gradient bands — subtle, stacked, right-shifted */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          {/* Band 1 — widest, middle position */}
          <div
            className="absolute"
            style={{ left: "38%", bottom: "12%", width: "62%", height: "48px", background: "linear-gradient(to right, #02092d, #1f2e74)", borderRadius: "4px" }}
          />
          {/* Band 2 — right shifted, above band 1 */}
          <div
            className="absolute"
            style={{ left: "55%", bottom: "22%", width: "45%", height: "48px", background: "linear-gradient(to right, #02092d, #000d4a)", opacity: 0.61, borderRadius: "4px" }}
          />
          {/* Band 3 — right shifted, below band 1 */}
          <div
            className="absolute"
            style={{ left: "55%", bottom: "2%", width: "45%", height: "48px", background: "linear-gradient(to right, #02092d, rgba(29,43,111,0.79))", opacity: 0.61, borderRadius: "4px" }}
          />
        </div>

        <div className="relative z-10 max-w-[700px] mx-auto">
          <p className="text-[12px] lg:text-[14px] font-bold uppercase tracking-[2.6px] text-[#ebf0ff] mb-5">
            File transfer with nothing in between.
          </p>
          <h1 className="text-[36px] sm:text-[48px] lg:text-[64px] font-bold leading-[1.15] mb-6">
            <span className="text-[#ebf0ff]">Wetransfer but </span>
            <span className="text-[#2c64ff]">faster</span>
          </h1>
          <p className="text-[14px] lg:text-[16px] leading-[1.65] text-[#ebf0ff]/80 max-w-[560px] mx-auto mb-8">
            Your files never touch a server. Spize creates a direct tunnel between you and your recipient — encrypted, instant, and completely private. Drop a file, share a link, done.
          </p>
          <a
            href="https://github.com/icaroholding/spize/releases"
            className="inline-block px-8 py-4 text-[16px] font-bold text-white bg-[#2c64ff] rounded-[11px] hover:opacity-90 transition-opacity"
          >
            Download Spize
          </a>
        </div>
      </section>

      {/* ── Features ── */}
      <section id="features" className="relative py-16 lg:py-20 px-6 lg:px-16">
        <div className="max-w-5xl mx-auto">
          <p className="text-[12px] font-bold uppercase tracking-[2.6px] text-[#2c64ff] text-center mb-3">
            Why Spize
          </p>
          <h2 className="text-[28px] lg:text-[36px] font-bold text-center text-[#ebf0ff] mb-12">
            Everything you need, nothing you don't
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {[
              { title: "No upload, ever", desc: "Files never leave your machine until someone downloads them. No waiting for uploads to finish.", icon: "⚡" },
              { title: "Resumable downloads", desc: "Connection dropped at 80%? Downloads pick up exactly where they left off.", icon: "🔄" },
              { title: "Encrypted tunnel", desc: "All transfers go through an encrypted Cloudflare Tunnel. Optional password protection.", icon: "🔒" },
              { title: "Persistent links", desc: "Your link stays the same even if your tunnel reconnects. Share once, download anytime.", icon: "🔗" },
              { title: "Folder sharing", desc: "Share entire folders. Streamed as .tar on-the-fly — no temp files, no size limits.", icon: "📁" },
              { title: "Zero accounts", desc: "Recipients don't need an account. Click the link and download. That's it.", icon: "👤" },
            ].map((f) => (
              <div key={f.title} className="p-5 rounded-[14px] border border-[#1a3dbf] bg-[#010b3c]/60">
                <div className="text-2xl mb-3">{f.icon}</div>
                <h3 className="text-[15px] font-bold text-[#ebf0ff] mb-1.5">{f.title}</h3>
                <p className="text-[13px] leading-[1.6] text-[#7d9fff]">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── How it works ── */}
      <section id="how" className="py-16 lg:py-20 px-6 lg:px-16">
        <div className="max-w-4xl mx-auto">
          <p className="text-[12px] font-bold uppercase tracking-[2.6px] text-[#2c64ff] text-center mb-3">
            Simple as 1-2-3
          </p>
          <h2 className="text-[28px] lg:text-[36px] font-bold text-center text-[#ebf0ff] mb-12">
            How it works
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              { step: "01", title: "Drop your file", desc: "Drag a file or folder into the app. Or click to select." },
              { step: "02", title: "Share the link", desc: "Get an instant link. Send it via WhatsApp, email, Slack — whatever works." },
              { step: "03", title: "Direct download", desc: "Your recipient opens the link and downloads directly from your machine." },
            ].map((s) => (
              <div key={s.step} className="text-center">
                <div className="text-[36px] font-bold text-[#2c64ff] mb-3">{s.step}</div>
                <h3 className="text-[16px] font-bold text-[#ebf0ff] mb-2">{s.title}</h3>
                <p className="text-[13px] leading-[1.6] text-[#7d9fff]">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Comparison ── */}
      <section className="py-16 lg:py-20 px-6 lg:px-16">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-[28px] lg:text-[36px] font-bold text-center text-[#ebf0ff] mb-12">
            Spize vs the rest
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px]">
              <thead>
                <tr className="border-b border-[#1a3dbf]">
                  <th className="pb-3 font-bold text-[#7d9fff]"></th>
                  <th className="pb-3 font-bold text-[#2c64ff]">Spize</th>
                  <th className="pb-3 font-bold text-[#7d9fff]">WeTransfer</th>
                  <th className="pb-3 font-bold text-[#7d9fff]">Google Drive</th>
                </tr>
              </thead>
              <tbody>
                {[
                  ["Upload required", "No", "Yes", "Yes"],
                  ["File size limit", "None", "2 GB free", "15 GB free"],
                  ["Resumable", "Yes", "No", "Partial"],
                  ["P2P direct", "Yes", "No", "No"],
                  ["Account needed", "No", "No", "Yes"],
                  ["Password protect", "Yes", "Paid", "No"],
                  ["Link persistence", "Yes", "7 days", "Until deleted"],
                ].map(([feature, sp, we, gd]) => (
                  <tr key={feature} className="border-b border-[#1a3dbf]/30">
                    <td className="py-3 text-[#ebf0ff] font-medium">{feature}</td>
                    <td className="py-3 text-[#2cff30] font-bold">{sp}</td>
                    <td className="py-3 text-[#7d9fff]">{we}</td>
                    <td className="py-3 text-[#7d9fff]">{gd}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* ── FAQ ── */}
      <section id="faq" className="py-16 lg:py-20 px-6 lg:px-16">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-[28px] lg:text-[36px] font-bold text-center text-[#ebf0ff] mb-12">
            FAQ
          </h2>
          <div className="space-y-4">
            {[
              { q: "How does it work without uploading?", a: "Spize runs a local server on your machine and creates an encrypted tunnel through Cloudflare. When someone opens your link, they download directly from your computer." },
              { q: "What happens when my computer goes to sleep?", a: "Spize prevents sleep while you have active shares. If your Mac does sleep, the tunnel auto-reconnects when you wake up and the same link works again." },
              { q: "Is there a file size limit?", a: "No. Since files aren't uploaded anywhere, there's no size limit. We've tested with files over 50GB." },
              { q: "Is it secure?", a: "All traffic goes through an encrypted Cloudflare Tunnel (TLS). You can also add a password to any share." },
              { q: "What if the download gets interrupted?", a: "Spize supports HTTP Range requests. Downloads resume from where they left off." },
              { q: "Does the recipient need to install anything?", a: "No. They just open the link in any browser and click Download." },
            ].map((item) => (
              <div key={item.q} className="p-4 rounded-[14px] border border-[#1a3dbf] bg-[#010b3c]/40">
                <h3 className="text-[14px] font-bold text-[#ebf0ff] mb-1.5">{item.q}</h3>
                <p className="text-[13px] leading-[1.6] text-[#7d9fff]">{item.a}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ── */}
      <section className="py-16 lg:py-20 px-6 text-center">
        <h2 className="text-[28px] lg:text-[36px] font-bold text-[#ebf0ff] mb-4">
          Ready to transfer?
        </h2>
        <p className="text-[15px] text-[#7d9fff] mb-8 max-w-md mx-auto">
          Download Spize for Mac and start sharing files in seconds.
        </p>
        <a
          href="https://github.com/icaroholding/spize/releases"
          className="inline-block px-8 py-4 text-[16px] font-bold text-white bg-[#2c64ff] rounded-[11px] hover:opacity-90 transition-opacity"
        >
          Download for Mac
        </a>
        <p className="text-[12px] text-[#7d9fff]/50 mt-3">macOS 12+ · Apple Silicon & Intel</p>
      </section>

      {/* ── Footer ── */}
      <footer className="border-t border-[#1a3dbf]/30 px-6 lg:px-16 py-6">
        <div className="max-w-5xl mx-auto flex flex-col md:flex-row items-center justify-between gap-3">
          <img src="/logo.svg" alt="Spize" className="h-[24px] opacity-50" />
          <div className="flex items-center gap-5 text-[13px] text-[#7d9fff]">
            <a href="#" className="hover:opacity-80 transition-opacity">Privacy</a>
            <a href="#" className="hover:opacity-80 transition-opacity">Terms</a>
            <a href="https://github.com/icaroholding/spize" className="hover:opacity-80 transition-opacity">GitHub</a>
          </div>
          <p className="text-[12px] text-[#7d9fff]/40">© 2026 Spize</p>
        </div>
      </footer>
    </main>
  );
}

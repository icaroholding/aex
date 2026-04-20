import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Spize — File transfer with nothing in between",
  description: "Your files never touch a server. Spize creates a direct tunnel between you and your recipient — encrypted, instant, and completely private.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-[#02092d] text-[#ebf0ff] antialiased">{children}</body>
    </html>
  );
}

import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Providers } from "@/components/providers";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "AgentTrust — Security Operations Console",
  description: "Permissioned Ledger Simulator for Verifiable Identity, Bounded Authorization, and Accountability of Autonomous AI Agents",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable} dark`} suppressHydrationWarning>
      <body className="min-h-screen bg-[var(--bg)] text-[var(--fg)] font-sans antialiased tabular-nums selection:bg-[var(--emerald)] selection:text-[var(--accent-fg)]">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}

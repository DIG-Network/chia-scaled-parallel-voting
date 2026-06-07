import type { Metadata, Viewport } from "next";
import { Fraunces, IBM_Plex_Sans, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";
import Navbar from "./components/Navbar";
import StoreProvider from "./StoreProvider";
import WalletInitializer from "./components/WalletInitializer";

// Editorial display serif for headings — gives the governance UI gravitas
// and a distinctive voice that avoids the generic all-sans AI look.
const fraunces = Fraunces({
  subsets: ["latin"],
  // Variable font: omit `weight` so the full 100–900 axis ships, which
  // lets `font-weight` in CSS interpolate freely. `axes`/`opsz` may only
  // be set when weight is variable.
  axes: ["opsz"],
  variable: "--font-fraunces",
  display: "swap",
});

// Neutral, highly legible interface sans for body copy.
const plexSans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-plex-sans",
  display: "swap",
});

// Ledger monospace for every hex id / numeric value.
const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: "CHIP Voting",
    template: "%s · CHIP Voting",
  },
  description:
    "On-chain voting for Chia — Election Singleton + CAT collateral + Groth16 finalization",
};

export const viewport: Viewport = {
  themeColor: "#0a0d15",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${fraunces.variable} ${plexSans.variable} ${plexMono.variable}`}
    >
      <body className="min-h-screen">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[2000] focus:rounded-lg focus:bg-[var(--color-accent)] focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-[var(--accent-contrast)]"
        >
          Skip to content
        </a>
        <StoreProvider>
          <WalletInitializer />
          <Navbar />
          <div id="main-content" className="pt-16">
            {children}
          </div>
        </StoreProvider>
      </body>
    </html>
  );
}

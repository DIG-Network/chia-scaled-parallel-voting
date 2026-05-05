import type { Metadata } from "next";
import "./globals.css";
import Navbar from "./components/Navbar";
import StoreProvider from "./StoreProvider";
import WalletInitializer from "./components/WalletInitializer";

export const metadata: Metadata = {
  title: "CHIP Voting",
  description:
    "On-chain voting for Chia — Election Singleton + CAT collateral + Groth16 finalization",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <StoreProvider>
          <WalletInitializer />
          <Navbar />
          <div className="pt-16">{children}</div>
        </StoreProvider>
      </body>
    </html>
  );
}

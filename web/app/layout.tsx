import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Tawny",
  description: "Quiet eyes on every endpoint.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}

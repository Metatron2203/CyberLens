import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CyberLens",
  description: "Análisis de indicadores asociados al phishing",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  );
}

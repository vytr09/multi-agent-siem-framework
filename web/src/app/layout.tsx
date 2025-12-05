import type { Metadata } from "next";
import { Montserrat, Be_Vietnam_Pro } from "next/font/google";
import "./globals.css";

const montserrat = Montserrat({
  subsets: ["latin"],
  variable: "--font-montserrat",
  display: "swap",
});

const beVietnamPro = Be_Vietnam_Pro({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-be-vietnam-pro",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Multi-Agent SIEM Dashboard",
  description: "Advanced SIEM Dashboard with Multi-Agent Orchestration",
};

import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";

import { ToastProvider } from "@/components/ui/toast-notification";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${montserrat.variable} ${beVietnamPro.variable} bg-neutral-900 text-neutral-100 font-sans antialiased`}>
        <ToastProvider>
          <div className="flex h-screen overflow-hidden">
            <Sidebar />
            <div className="flex flex-1 flex-col overflow-hidden">
              <Header />
              <main className="flex-1 overflow-y-auto bg-neutral-950 p-6">
                {children}
              </main>
            </div>
          </div>
        </ToastProvider>
      </body>
    </html>
  );
}

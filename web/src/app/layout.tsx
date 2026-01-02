import type { Metadata } from "next";
import "./globals.css";
// Google Fonts temporarily removed due to Next.js Turbopack issue
// import { Montserrat, Be_Vietnam_Pro } from "next/font/google";

// const montserrat = Montserrat({
//   subsets: ["latin"],
//   variable: "--font-montserrat",
//   display: "swap",
// });

// const beVietnamPro = Be_Vietnam_Pro({
//   subsets: ["latin"],
//   weight: ["400", "500", "600", "700"],
//   variable: "--font-be-vietnam-pro",
//   display: "swap",
// });

export const metadata: Metadata = {
  title: "Multi-Agent SIEM Dashboard",
  description: "Advanced SIEM Dashboard with Multi-Agent Orchestration",
};

import { ToastProvider } from "@/components/ui/toast-notification";
import { ThemeProvider } from "@/components/theme-provider"
import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { NotificationProvider } from "@/contexts/notification-context"



export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`font-sans antialiased`} suppressHydrationWarning={true}>
        <ToastProvider>
          <NotificationProvider>
            <ThemeProvider
              attribute="class"
              defaultTheme="system"
              enableSystem
              disableTransitionOnChange
            >
              <div className="flex h-screen bg-background text-foreground">
                <Sidebar />
                <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
                  <Header />
                  <main className="flex-1 overflow-auto p-6 scroll-smooth">
                    {children}
                  </main>
                </div>
              </div>
            </ThemeProvider>
          </NotificationProvider>
        </ToastProvider>
      </body>
    </html>
  );
}

import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { ThemeProvider } from "next-themes";
import { Toaster } from "@/components/ui/sonner";
import { SessionProvider } from "@/components/providers/SessionProvider";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: {
    default: "샌드박스 다이어리 - 기술 블로그 및 보안 실험실",
    template: "%s | 샌드박스 다이어리",
  },
  description: "보안 테스팅, 기술 실습, 그리고 일상을 기록하는 개인 기술 블로그이자 실험실인 샌드박스 다이어리입니다.",
  keywords: ["보안", "기술 블로그", "샌드박스 다이어리", "해킹", "개발", "실험실", "보안 테스팅"],
  authors: [{ name: "샌드박스 다이어리" }],
  creator: "샌드박스 다이어리",
  publisher: "샌드박스 다이어리",
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
  openGraph: {
    type: "website",
    locale: "ko_KR",
    siteName: "샌드박스 다이어리",
    title: "샌드박스 다이어리 - 기술 블로그 및 보안 실험실",
    description: "보안 테스팅, 기술 실습, 그리고 일상을 기록하는 개인 기술 블로그이자 실험실인 샌드박스 다이어리입니다.",
  },
  twitter: {
    card: "summary_large_image",
    title: "샌드박스 다이어리 - 기술 블로그 및 보안 실험실",
    description: "보안 테스팅, 기술 실습, 그리고 일상을 기록하는 개인 기술 블로그이자 실험실인 샌드박스 다이어리입니다.",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="ko" suppressHydrationWarning>
      <head>
        <link
          rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css"
        />
      </head>
      <body className={inter.className}>
        <SessionProvider>
          <ThemeProvider
            attribute="class"
            defaultTheme="system"
            enableSystem
            disableTransitionOnChange
          >
            {children}
            <Toaster />
          </ThemeProvider>
        </SessionProvider>
      </body>
    </html>
  );
}

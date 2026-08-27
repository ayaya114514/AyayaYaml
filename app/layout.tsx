import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
});

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
});

export const metadata: Metadata = {
  title: 'AyayaYaml — YAML 与代理配置工具',
  description: '浏览器本地运行的 YAML 编辑、格式化、语法检查、JSON 转换与代理链接解析工具。',
  openGraph: {
    title: 'AyayaYaml — YAML 与代理配置工具',
    description: 'YAML 与代理配置，本地处理更安心。',
    type: 'website',
    locale: 'zh_CN',
    images: [{ url: '/og.png', width: 1730, height: 909, alt: 'AyayaYaml' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AyayaYaml — YAML 与代理配置工具',
    description: 'YAML 与代理配置，本地处理更安心。',
    images: ['/og.png'],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-CN">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>
        {children}
      </body>
    </html>
  );
}

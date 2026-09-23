import type { Metadata, Viewport } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';

const isGitHubPages = process.env.GITHUB_PAGES === 'true';
const repositoryName = process.env.GITHUB_REPOSITORY?.split('/')[1] ?? 'AyayaYaml';
const isUserSite = repositoryName.endsWith('.github.io');
const basePath = isGitHubPages && !isUserSite ? `/${repositoryName}` : '';
const publicOrigin = 'https://ayaya114514.github.io';
const ogImage = isGitHubPages ? `${publicOrigin}${basePath}/og.png` : '/og.png';
const favicon = `${basePath}/favicon.svg`;

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
});

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
});

export const metadata: Metadata = {
  metadataBase: isGitHubPages
    ? new URL(`${publicOrigin}/`)
    : undefined,
  title: 'AyayaYaml',
  description: '在浏览器本地完成 YAML / JSON 编辑、格式化与互转，以及代理分享链接与 Mihomo、sing-box 配置的互转。',
  icons: { icon: favicon },
  openGraph: {
    title: 'AyayaYaml',
    description: 'YAML 与代理配置，本地处理更安心。',
    type: 'website',
    locale: 'zh_CN',
    images: [{ url: ogImage, width: 1730, height: 909, alt: 'AyayaYaml' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AyayaYaml',
    description: 'YAML 与代理配置，本地处理更安心。',
    images: [ogImage],
  },
};

export const viewport: Viewport = {
  themeColor: '#0b0b0b',
  colorScheme: 'dark',
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

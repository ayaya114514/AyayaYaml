import type { NextConfig } from 'next';

const isGitHubPages = process.env.GITHUB_PAGES === 'true';
const repositoryName = process.env.GITHUB_REPOSITORY?.split('/')[1] ?? 'AyayaYaml';
const isUserSite = repositoryName.endsWith('.github.io');
const basePath = isGitHubPages && !isUserSite ? `/${repositoryName}` : '';

const nextConfig: NextConfig = isGitHubPages
  ? {
      output: 'export',
      trailingSlash: true,
      basePath,
    }
  : {};

export default nextConfig;

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { scanRegistry } from '../src/scanners/registry.js';
import { resetCounter } from '../src/utils/helpers.js';

function makePypiResponse(overrides: {
  author?: string;
  authorEmail?: string;
  projectUrls?: Record<string, string>;
  releases?: Record<string, Array<{ upload_time?: string }>>;
} = {}) {
  return {
    info: {
      author: overrides.author,
      author_email: overrides.authorEmail,
      project_urls: overrides.projectUrls,
    },
    releases: overrides.releases ?? {},
  };
}

function makeNpmResponse(overrides: {
  time?: Record<string, string>;
  versions?: Record<string, unknown>;
  maintainers?: Array<{ name: string; email?: string }>;
  homepage?: string;
  repository?: { url?: string };
} = {}) {
  return {
    name: 'some-package',
    'dist-tags': { latest: '1.0.0' },
    ...overrides,
  };
}

describe('registry scanner', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    resetCounter();
  });

  describe('PyPI deep analysis', () => {
    it('flags PyPI packages published less than 30 days ago', async () => {
      const recentDate = new Date(Date.now() - 10 * 86400000).toISOString();
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => makePypiResponse({
          releases: {
            '0.1.0': [{ upload_time: recentDate }],
          },
        }),
      });

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['some-package'],
      });

      const ageFinding = findings.find(f => f.title === 'Recently Published PyPI Package');
      expect(ageFinding).toBeDefined();
      expect(ageFinding!.severity).toBe('medium');
      expect(ageFinding!.category).toBe('supply-chain');
      expect(ageFinding!.references).toContain('MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering');
    });

    it('does not flag old PyPI packages for age', async () => {
      const oldDate = new Date(Date.now() - 365 * 86400000).toISOString();
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => makePypiResponse({
          author: 'Author',
          projectUrls: { Repository: 'https://github.com/example/repo' },
          releases: {
            '0.1.0': [{ upload_time: oldDate }],
            '0.2.0': [{ upload_time: new Date().toISOString() }],
          },
        }),
      });

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['some-package'],
      });

      const ageFinding = findings.find(f => f.title === 'Recently Published PyPI Package');
      expect(ageFinding).toBeUndefined();
    });

    it('flags PyPI packages with a single version', async () => {
      const oldDate = new Date(Date.now() - 365 * 86400000).toISOString();
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => makePypiResponse({
          author: 'Author',
          projectUrls: { Repository: 'https://github.com/example/repo' },
          releases: {
            '0.1.0': [{ upload_time: oldDate }],
          },
        }),
      });

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['some-package'],
      });

      const versionFinding = findings.find(f => f.title === 'Single-Version PyPI Package');
      expect(versionFinding).toBeDefined();
      expect(versionFinding!.severity).toBe('low');
      expect(versionFinding!.references).toContain('MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering');
    });

    it('does not flag PyPI packages with multiple versions', async () => {
      const oldDate = new Date(Date.now() - 365 * 86400000).toISOString();
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => makePypiResponse({
          author: 'Author',
          projectUrls: { Repository: 'https://github.com/example/repo' },
          releases: {
            '0.1.0': [{ upload_time: oldDate }],
            '0.2.0': [{ upload_time: new Date().toISOString() }],
          },
        }),
      });

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['some-package'],
      });

      const versionFinding = findings.find(f => f.title === 'Single-Version PyPI Package');
      expect(versionFinding).toBeUndefined();
    });

    it('flags PyPI packages missing source repository', async () => {
      const oldDate = new Date(Date.now() - 365 * 86400000).toISOString();
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => makePypiResponse({
          releases: {
            '0.1.0': [{ upload_time: oldDate }],
            '0.2.0': [{ upload_time: new Date().toISOString() }],
          },
        }),
      });

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['some-package'],
      });

      const repoFinding = findings.find(f => f.title === 'PyPI Package Missing Source Repository');
      expect(repoFinding).toBeDefined();
      expect(repoFinding!.severity).toBe('low');
      expect(repoFinding!.references).toContain('MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering');
    });

    it('does not flag PyPI packages with Repository in project_urls', async () => {
      const oldDate = new Date(Date.now() - 365 * 86400000).toISOString();
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => makePypiResponse({
          author: 'Author',
          projectUrls: { Repository: 'https://github.com/example/repo' },
          releases: {
            '0.1.0': [{ upload_time: oldDate }],
            '0.2.0': [{ upload_time: new Date().toISOString() }],
          },
        }),
      });

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['some-package'],
      });

      const repoFinding = findings.find(f => f.title === 'PyPI Package Missing Source Repository');
      expect(repoFinding).toBeUndefined();
    });

    it('does not flag PyPI packages with Source in project_urls', async () => {
      const oldDate = new Date(Date.now() - 365 * 86400000).toISOString();
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => makePypiResponse({
          author: 'Author',
          projectUrls: { Source: 'https://gitlab.com/example/repo' },
          releases: {
            '0.1.0': [{ upload_time: oldDate }],
            '0.2.0': [{ upload_time: new Date().toISOString() }],
          },
        }),
      });

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['some-package'],
      });

      const repoFinding = findings.find(f => f.title === 'PyPI Package Missing Source Repository');
      expect(repoFinding).toBeUndefined();
    });

    it('flags single-author PyPI package without source repo', async () => {
      const oldDate = new Date(Date.now() - 365 * 86400000).toISOString();
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => makePypiResponse({
          author: 'OnlyAuthor',
          releases: {
            '0.1.0': [{ upload_time: oldDate }],
            '0.2.0': [{ upload_time: new Date().toISOString() }],
          },
        }),
      });

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['some-package'],
      });

      const authorFinding = findings.find(f => f.title === 'Single Author PyPI Package Without Source Repo');
      expect(authorFinding).toBeDefined();
      expect(authorFinding!.severity).toBe('medium');
      expect(authorFinding!.description).toContain('OnlyAuthor');
    });

    it('does not flag single-author PyPI package when source repo exists', async () => {
      const oldDate = new Date(Date.now() - 365 * 86400000).toISOString();
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => makePypiResponse({
          author: 'OnlyAuthor',
          projectUrls: { Repository: 'https://github.com/example/repo' },
          releases: {
            '0.1.0': [{ upload_time: oldDate }],
            '0.2.0': [{ upload_time: new Date().toISOString() }],
          },
        }),
      });

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['some-package'],
      });

      const authorFinding = findings.find(f => f.title === 'Single Author PyPI Package Without Source Repo');
      expect(authorFinding).toBeUndefined();
    });

    it('flags PyPI package not found (404)', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({}),
      });

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['nonexistent-pkg'],
      });

      const notFound = findings.find(f => f.title === 'Package Not Found on PyPI');
      expect(notFound).toBeDefined();
      expect(notFound!.severity).toBe('critical');
    });

    it('surfaces medium finding for PyPI HTTP errors', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({}),
      });

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['some-package'],
      });

      const notFound = findings.find(f => f.title === 'Package Not Found on PyPI');
      expect(notFound).toBeDefined();
      expect(notFound!.severity).toBe('medium');
      expect(notFound!.description).toContain('HTTP 500');
    });

    it('surfaces medium finding for PyPI network errors', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network timeout'));

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['some-package'],
      });

      const notFound = findings.find(f => f.title === 'Package Not Found on PyPI');
      expect(notFound).toBeDefined();
      expect(notFound!.severity).toBe('medium');
      expect(notFound!.description).toContain('Network timeout');
    });

    it('returns empty findings for pypi server with no package args', async () => {
      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: [],
      });

      expect(findings).toHaveLength(0);
    });

    it('uses earliest upload time across all releases for age check', async () => {
      const oldDate = new Date(Date.now() - 365 * 86400000).toISOString();
      const recentDate = new Date(Date.now() - 5 * 86400000).toISOString();
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => makePypiResponse({
          releases: {
            '0.1.0': [{ upload_time: oldDate }],
            '0.2.0': [{ upload_time: recentDate }],
          },
        }),
      });

      const findings = await scanRegistry('test-server', {
        command: 'uvx',
        args: ['some-package'],
      });

      const ageFinding = findings.find(f => f.title === 'Recently Published PyPI Package');
      expect(ageFinding).toBeUndefined();
    });
  });

  describe('npm registry checks (validation)', () => {
    it('flags npm packages not found (404)', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({}),
      });

      const findings = await scanRegistry('test-server', {
        command: 'npx',
        args: ['-y', 'nonexistent-pkg'],
      });

      const notFound = findings.find(f => f.title === 'Package Not Found on npm');
      expect(notFound).toBeDefined();
      expect(notFound!.severity).toBe('critical');
    });

    it('does not flag well-established npm packages', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => makeNpmResponse({
          time: { created: new Date(Date.now() - 365 * 86400000).toISOString() },
          versions: { '1.0.0': {}, '1.1.0': {}, '2.0.0': {} },
          maintainers: [{ name: 'author1' }, { name: 'author2' }],
          repository: { url: 'https://github.com/example/repo' },
        }),
      });

      const findings = await scanRegistry('test-server', {
        command: 'npx',
        args: ['-y', 'some-package'],
      });

      expect(findings).toHaveLength(0);
    });
  });

  describe('non-registry server types', () => {
    it('returns empty findings for unknown server types', async () => {
      const findings = await scanRegistry('test-server', {
        command: 'docker',
        args: ['run', 'some-image'],
      });

      expect(findings).toHaveLength(0);
    });
  });
});

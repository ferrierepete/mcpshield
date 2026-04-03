import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function loadJSON<T>(filename: string): T {
  const raw = readFileSync(join(__dirname, filename), 'utf-8');
  return JSON.parse(raw) as T;
}

interface TrustedPackagesData {
  packages: string[];
  trustedScopes: string[];
}

interface RiskyPackagesData {
  packages: string[];
}

interface SuspiciousPatternsData {
  suspiciousUrlPatterns: string[];
  typosquatPatterns: Array<{ original: string; pattern: string }>;
}

let _trusted: TrustedPackagesData | null = null;
let _risky: RiskyPackagesData | null = null;
let _suspicious: SuspiciousPatternsData | null = null;

export function getTrustedPackages(): TrustedPackagesData {
  if (!_trusted) _trusted = loadJSON<TrustedPackagesData>('trusted-packages.json');
  return _trusted;
}

export function getRiskyPackages(): RiskyPackagesData {
  if (!_risky) _risky = loadJSON<RiskyPackagesData>('risky-packages.json');
  return _risky;
}

export function getSuspiciousPatterns(): SuspiciousPatternsData {
  if (!_suspicious) _suspicious = loadJSON<SuspiciousPatternsData>('suspicious-patterns.json');
  return _suspicious;
}

export function isTrustedPackage(pkg: string): boolean {
  const data = getTrustedPackages();
  if (data.packages.includes(pkg)) return true;
  return data.trustedScopes.some(scope => pkg.startsWith(scope));
}

export function isRiskyPackage(pkg: string): boolean {
  return getRiskyPackages().packages.includes(pkg);
}

export function resetDataCache(): void {
  _trusted = null;
  _risky = null;
  _suspicious = null;
}

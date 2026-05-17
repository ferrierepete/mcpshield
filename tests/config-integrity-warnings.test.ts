import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from 'vitest';
import { emitConfigIntegrityWarnings } from '../src/config/index.js';
import type { MCPShieldConfig } from '../src/config/index.js';

describe('emitConfigIntegrityWarnings', () => {
  let warnSpy: MockInstance;

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  it('should not warn on empty config', () => {
    emitConfigIntegrityWarnings({});
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('should not warn on config with no sensitive fields', () => {
    const config: MCPShieldConfig = {
      severityThreshold: 'high',
      format: 'json',
      registry: true,
    };
    emitConfigIntegrityWarnings(config);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('should warn when ignore rules are present', () => {
    const config: MCPShieldConfig = {
      ignore: ['MCPS-001', 'MCPS-003'],
    };
    emitConfigIntegrityWarnings(config);
    expect(warnSpy).toHaveBeenCalledWith(
      '⚠ .mcpshieldrc contains 2 ignore rules — verify these were not maliciously added'
    );
  });

  it('should warn with singular form for single ignore rule', () => {
    const config: MCPShieldConfig = {
      ignore: ['MCPS-001'],
    };
    emitConfigIntegrityWarnings(config);
    expect(warnSpy).toHaveBeenCalledWith(
      '⚠ .mcpshieldrc contains 1 ignore rule — verify these were not maliciously added'
    );
  });

  it('should warn when trusted packages are present', () => {
    const config: MCPShieldConfig = {
      trustedPackages: ['@myorg/pkg1', 'pkg2'],
    };
    emitConfigIntegrityWarnings(config);
    expect(warnSpy).toHaveBeenCalledWith(
      '⚠ .mcpshieldrc adds 2 trusted packages — verify these are legitimate'
    );
  });

  it('should warn with singular form for single trusted package', () => {
    const config: MCPShieldConfig = {
      trustedPackages: ['@myorg/pkg'],
    };
    emitConfigIntegrityWarnings(config);
    expect(warnSpy).toHaveBeenCalledWith(
      '⚠ .mcpshieldrc adds 1 trusted package — verify these are legitimate'
    );
  });

  it('should warn when minConfidence exceeds 0.8', () => {
    const config: MCPShieldConfig = {
      minConfidence: 0.9,
    };
    emitConfigIntegrityWarnings(config);
    expect(warnSpy).toHaveBeenCalledWith(
      '⚠ .mcpshieldrc sets high minConfidence (0.9) — this may suppress real findings'
    );
  });

  it('should not warn when minConfidence is exactly 0.8', () => {
    const config: MCPShieldConfig = {
      minConfidence: 0.8,
    };
    emitConfigIntegrityWarnings(config);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('should not warn when minConfidence is below 0.8', () => {
    const config: MCPShieldConfig = {
      minConfidence: 0.5,
    };
    emitConfigIntegrityWarnings(config);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('should emit multiple warnings when multiple conditions are met', () => {
    const config: MCPShieldConfig = {
      ignore: ['MCPS-001'],
      trustedPackages: ['bad-pkg'],
      minConfidence: 0.95,
    };
    emitConfigIntegrityWarnings(config);
    expect(warnSpy).toHaveBeenCalledTimes(3);
    expect(warnSpy).toHaveBeenCalledWith(
      '⚠ .mcpshieldrc contains 1 ignore rule — verify these were not maliciously added'
    );
    expect(warnSpy).toHaveBeenCalledWith(
      '⚠ .mcpshieldrc adds 1 trusted package — verify these are legitimate'
    );
    expect(warnSpy).toHaveBeenCalledWith(
      '⚠ .mcpshieldrc sets high minConfidence (0.95) — this may suppress real findings'
    );
  });

  it('should not warn on empty ignore array', () => {
    const config: MCPShieldConfig = {
      ignore: [],
    };
    emitConfigIntegrityWarnings(config);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('should not warn on empty trustedPackages array', () => {
    const config: MCPShieldConfig = {
      trustedPackages: [],
    };
    emitConfigIntegrityWarnings(config);
    expect(warnSpy).not.toHaveBeenCalled();
  });
});

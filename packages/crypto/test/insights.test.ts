import { describe, expect, it } from 'vitest';
import {
  analyzeHealth,
  diffEnvironments,
  generateKey,
  resolveReferences,
  unwrapAccountKeyWithPasskey,
  wrapAccountKeyWithPasskey,
} from '../src';

describe('references', () => {
  it('resolves nested references', () => {
    const r = resolveReferences([
      { name: 'HOST', value: 'db.internal' },
      { name: 'PORT', value: '5432' },
      { name: 'ADDR', value: '${HOST}:${PORT}' },
      { name: 'URL', value: 'postgres://app@${ADDR}/billing' },
    ]);
    expect(r.get('URL')).toEqual({ value: 'postgres://app@db.internal:5432/billing', references: ['ADDR'] });
  });
  it('supports escaping', () => {
    expect(resolveReferences([{ name: 'A', value: 'cost $${PRICE}' }]).get('A')!.value).toBe('cost ${PRICE}');
  });
  it('reports missing references', () => {
    expect(resolveReferences([{ name: 'A', value: '${NOPE}' }]).get('A')!.error).toMatch(/does not exist/);
  });
  it('detects cycles without hanging', () => {
    const r = resolveReferences([
      { name: 'A', value: '${B}' },
      { name: 'B', value: '${C}' },
      { name: 'C', value: '${A}' },
    ]);
    expect(r.get('A')!.error).toMatch(/Circular/);
    expect(resolveReferences([{ name: 'S', value: 'x${S}' }]).get('S')!.error).toMatch(/Circular/);
  });
});

describe('health', () => {
  const now = Date.parse('2026-11-17T00:00:00Z');
  it('flags the classic mistakes', () => {
    const { findings, score } = analyzeHealth([
      { slug: 'development', name: 'Development', secrets: [
        { name: 'STRIPE_SECRET_KEY', value: 'sk_live_51HxYzABCDEFGH' },
        { name: 'DB_PASSWORD', value: 'hunter2-shared-value' },
        { name: 'API_TOKEN', value: 'changeme' },
      ] },
      { slug: 'production', name: 'Production', secrets: [
        { name: 'STRIPE_SECRET_KEY', value: 'sk_test_51HxYz' },
        { name: 'DB_PASSWORD', value: 'hunter2-shared-value' },
        { name: 'REDIS_URL', value: 'redis://localhost:6379' },
        { name: 'JWT_SECRET', value: 'x9', updatedAt: '2025-01-01T00:00:00Z' },
        { name: 'LINK', value: '${MISSING}' },
      ] },
    ], now);
    const rules = findings.map((f) => `${f.environment}:${f.rule}`);
    expect(rules).toContain('Development:live-key-outside-production');
    expect(rules).toContain('Production:test-key-in-production');
    expect(rules).toContain('Development:shared-with-production');
    expect(rules).toContain('Production:localhost-in-production');
    expect(rules).toContain('Development:placeholder');
    expect(rules).toContain('Production:weak-value');
    expect(rules).toContain('Production:stale');
    expect(rules).toContain('Production:broken-reference');
    expect(findings[0]!.severity).toBe('critical');
    expect(score).toBeLessThan(30);
  });
  it('scores a clean setup at 100', () => {
    const { score, findings } = analyzeHealth([
      { slug: 'production', name: 'Production', secrets: [{ name: 'API_KEY', value: 'a'.repeat(10) + 'Zq81!kd0lPq' }] },
    ]);
    expect(findings).toEqual([]);
    expect(score).toBe(100);
  });
});

describe('diff', () => {
  it('classifies rows', () => {
    const rows = diffEnvironments([
      { slug: 'dev', name: 'Dev', secrets: [{ name: 'A', value: '1' }, { name: 'B', value: 'x' }, { name: 'C', value: 'same' }] },
      { slug: 'prod', name: 'Prod', secrets: [{ name: 'A', value: '2' }, { name: 'C', value: 'same' }] },
    ]);
    expect(rows.map((r) => [r.name, r.status])).toEqual([['A', 'differs'], ['B', 'missing'], ['C', 'same']]);
  });
});

describe('passkey wrapping', () => {
  it('round-trips and is bound to the credential', () => {
    const accountKey = generateKey();
    const prf = generateKey();
    const w = wrapAccountKeyWithPasskey(accountKey, prf, 'cred-1');
    expect(unwrapAccountKeyWithPasskey(w, prf, 'cred-1')).toEqual(accountKey);
    expect(() => unwrapAccountKeyWithPasskey(w, prf, 'cred-2')).toThrow();
    expect(() => unwrapAccountKeyWithPasskey(w, generateKey(), 'cred-1')).toThrow();
  });
});

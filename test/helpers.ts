import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { GuardDogEvent, InformerRecord, InventoryItem } from '../src/core/types.js';

const here = path.dirname(fileURLToPath(import.meta.url));

export function fixture(name: string): unknown {
  return JSON.parse(fs.readFileSync(path.join(here, '..', 'fixtures', name), 'utf8'));
}

export function record(overrides: Partial<InformerRecord> = {}): InformerRecord {
  return {
    id: 'GD-EXAMPLE-0001',
    ecosystem: 'npm',
    package: 'example-lib',
    affected: '>=1.0.0 <1.4.2',
    fixed: '1.4.2',
    severity: 'high',
    source: 'example-advisory-feed',
    link: 'https://example.invalid/advisories/GD-EXAMPLE-0001',
    publishedAt: '2026-10-20T08:00:00Z',
    verification: { status: 'unverified' },
    ...overrides,
  };
}

export function verified(by = 'reviewer@example.invalid'): InformerRecord['verification'] {
  return { status: 'verified', verifiedBy: by, verifiedAt: '2026-10-20T09:00:00Z' };
}

export function item(overrides: Partial<InventoryItem> = {}): InventoryItem {
  return {
    ecosystem: 'npm',
    name: 'example-lib',
    version: '1.2.0',
    service: 'shop-web',
    layer: 'application',
    ...overrides,
  };
}

export function event(
  kind: GuardDogEvent['kind'],
  attrs: GuardDogEvent['attrs'],
  overrides: Partial<GuardDogEvent> = {},
): GuardDogEvent {
  return {
    id: 'evt-1',
    ts: '2026-10-23T10:15:00Z',
    layer: 'application',
    service: 'shop-web',
    kind,
    attrs,
    masked: true,
    ...overrides,
  };
}

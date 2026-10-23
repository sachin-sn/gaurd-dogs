import { isIP } from 'node:net';
import path from 'node:path';
import type { GuardDogEvent, ResponseLevel, Severity } from '../core/types.js';
import { sanitizeEvidence } from './sanitize.js';

/**
 * Tier 1: deterministic rules. No model is involved. Tier 1 only ever suggests
 * observe (1) or alert (2). Containment is decided later by the panel and the
 * response gate.
 */

export interface RulesConfig {
  /** Directories served to the public. */
  webRoots: readonly string[];
  /** File extensions that a web server may execute. Lowercase, no dot. */
  executableExtensions: readonly string[];
  /** Actors (deploy tooling) allowed to write executable files into web roots. */
  allowedWriters: readonly string[];
  /** Allowed outbound hosts per service. '*' is the default for other services. Supports '*.example.com'. */
  egressAllowList: Readonly<Record<string, readonly string[]>>;
  /** Hosts the guard dogs themselves call (model API, alert sink). */
  guardDogEgress: readonly string[];
  /** Process names that serve web traffic. */
  webProcessNames: readonly string[];
  /** Child processes a web server should not normally start. */
  suspiciousChildren: readonly string[];
}

export const defaultRulesConfig: RulesConfig = {
  webRoots: ['/var/www/html', '/var/www/public', '/app/public'],
  executableExtensions: ['php', 'phtml', 'phar', 'pht', 'php5', 'php7', 'php8'],
  allowedWriters: [],
  egressAllowList: { '*': [] },
  guardDogEgress: [],
  webProcessNames: ['php-fpm', 'php', 'nginx', 'apache2', 'httpd', 'node'],
  suspiciousChildren: ['sh', 'bash', 'dash', 'zsh', 'nc', 'ncat', 'netcat', 'curl', 'wget', 'perl', 'python', 'python3'],
};

export interface RuleHit {
  ruleId: string;
  eventId: string;
  severity: Severity;
  /** Tier 1 never suggests more than an alert. */
  suggestedLevel: Extract<ResponseLevel, 1 | 2>;
  summary: string;
  /** Sanitised copies of the attacker-influenced values that triggered the rule. */
  evidence: Record<string, string>;
}

export interface Rule {
  id: string;
  description: string;
  evaluate(event: GuardDogEvent, config: RulesConfig): RuleHit | null;
}

function str(event: GuardDogEvent, key: string): string | null {
  const value = event.attrs[key];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function isUnder(file: string, root: string): boolean {
  const normalizedFile = path.posix.normalize(file);
  const normalizedRoot = path.posix.normalize(root).replace(/\/+$/, '');
  return normalizedFile === normalizedRoot || normalizedFile.startsWith(`${normalizedRoot}/`);
}

/** True when any dot-separated part after the first is an executable extension (catches `a.php.jpg`). */
function hasExecutableExtension(file: string, extensions: readonly string[]): boolean {
  const name = path.posix.basename(file).toLowerCase().replace(/[.\s]+$/, '');
  const parts = name.split('.').slice(1);
  return parts.some((part) => extensions.includes(part));
}

/** New executable file appears under a public web root, written by something other than deploy tooling. */
export const webrootNewExecutable: Rule = {
  id: 'drift.webroot-new-executable',
  description: 'An executable file was created or modified inside a public web root by an unexpected writer.',
  evaluate(event, config) {
    if (event.kind !== 'file.created' && event.kind !== 'file.modified') return null;
    const file = str(event, 'path');
    if (file === null) return null;
    if (!config.webRoots.some((root) => isUnder(file, root))) return null;
    if (!hasExecutableExtension(file, config.executableExtensions)) return null;
    const actor = str(event, 'actor');
    if (actor !== null && config.allowedWriters.includes(actor)) return null;
    return {
      ruleId: this.id,
      eventId: event.id,
      severity: 'high',
      suggestedLevel: 2,
      summary: `Executable file ${event.kind === 'file.created' ? 'created' : 'modified'} in a web root on ${event.service}`,
      evidence: {
        path: sanitizeEvidence(file),
        actor: sanitizeEvidence(actor ?? 'unknown'),
      },
    };
  },
};

function hostAllowed(host: string, allowed: readonly string[]): boolean {
  const h = host.toLowerCase();
  return allowed.some((entry) => {
    const e = entry.toLowerCase();
    if (e.startsWith('*.')) return h.endsWith(e.slice(1)) && h.length > e.length - 1;
    return h === e;
  });
}

/** Outbound connection to a host that is not on the service's allow-list. */
export const unexpectedOutbound: Rule = {
  id: 'drift.unexpected-outbound',
  description: 'A service connected to a host that is not on its egress allow-list.',
  evaluate(event, config) {
    if (event.kind !== 'net.outbound') return null;
    const host = str(event, 'host');
    if (host === null) return null;

    // The guard dogs' own model and alert traffic is exempt, but only when it
    // really comes from a guard dog. An application process cannot hide behind it.
    if (str(event, 'actor') === 'guard-dog' && hostAllowed(host, config.guardDogEgress)) return null;

    const allowed = config.egressAllowList[event.service] ?? config.egressAllowList['*'] ?? [];
    if (hostAllowed(host, allowed)) return null;

    const literalIp = isIP(host) !== 0;
    return {
      ruleId: this.id,
      eventId: event.id,
      severity: literalIp ? 'high' : 'medium',
      suggestedLevel: 2,
      summary: `${event.service} connected to ${literalIp ? 'a raw IP address' : 'a host'} outside its allow-list`,
      evidence: { host: sanitizeEvidence(host), actor: sanitizeEvidence(str(event, 'actor') ?? 'unknown') },
    };
  },
};

/** Matches 'php-fpm' and versioned names such as 'php-fpm8.3'. */
function isWebProcess(name: string, webProcessNames: readonly string[]): boolean {
  return webProcessNames.some((n) => {
    if (name === n) return true;
    return name.startsWith(n) && /^[\d.]+$/.test(name.slice(n.length));
  });
}

/** A web-serving process starts a shell or a network tool. */
export const webProcessSpawnsShell: Rule = {
  id: 'drift.web-process-spawns-shell',
  description: 'A web-serving process started a shell or network tool, a common webshell indicator.',
  evaluate(event, config) {
    if (event.kind !== 'process.spawned') return null;
    const parent = str(event, 'parent');
    const child = str(event, 'child');
    if (parent === null || child === null) return null;
    const parentName = path.posix.basename(parent).toLowerCase();
    const childName = path.posix.basename(child).toLowerCase();
    if (!isWebProcess(parentName, config.webProcessNames)) return null;
    if (!config.suspiciousChildren.includes(childName)) return null;
    return {
      ruleId: this.id,
      eventId: event.id,
      severity: 'high',
      suggestedLevel: 2,
      summary: `${parentName} started ${childName} on ${event.service}`,
      evidence: { parent: sanitizeEvidence(parent), child: sanitizeEvidence(child) },
    };
  },
};

export const defaultRules: readonly Rule[] = [webrootNewExecutable, unexpectedOutbound, webProcessSpawnsShell];

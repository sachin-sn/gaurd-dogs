/**
 * The model registry: the only models a guard dog may call, and where.
 *
 * Which model a dog calls is decided here, in configuration, before anything
 * runs. It is never decided by a dog's own reasoning and never by anything in
 * the evidence. The evidence comes from the systems under attack, so if a log
 * line (or a model reading one) could choose the model or the endpoint, an
 * attacker could send masked-but-still-sensitive logs to a server they control,
 * or steer a vote to a weak model. A dog receives a registered model and has no
 * way to name another.
 *
 * The registry also feeds the egress rule: the hosts a guard dog is allowed to
 * contact are derived from the models it can actually use, so the allow-list
 * cannot drift from the configuration.
 */

import { isIP } from 'node:net';

/** `small` for triage (tier 2), `large` for investigation and votes on containment (tier 3). */
export type ModelTier = 'small' | 'large';

/**
 * How the operator of the model handles what it is sent, as attested by the
 * deployer (the registry cannot check it). Ordered from weakest to strongest.
 */
export type ModelHandling = 'standard' | 'zero-retention' | 'self-hosted';

export const HANDLING_RANK: Readonly<Record<ModelHandling, number>> = {
  standard: 0,
  'zero-retention': 1,
  'self-hosted': 2,
};

export interface ModelSpec {
  /** The name used in the panel policy (`PanelMember.model`). Unique. */
  id: string;
  /** Who runs the model. Dogs on one provider share its outages and its policies. */
  provider: string;
  /**
   * The model lineage, such as one vendor's model line. Models of one family
   * tend to share blind spots, so the planner never puts two of them on the
   * same panel.
   */
  family: string;
  tier: ModelTier;
  /** The one HTTPS URL a dog on this model calls. No credentials, query string or fragment. */
  endpoint: string;
  handling: ModelHandling;
  /** The most characters of evidence sent in one call. */
  maxInputChars: number;
}

export interface RegisteredModel extends Readonly<ModelSpec> {
  /** The endpoint's host, lower-cased: what the egress allow-list needs. */
  readonly host: string;
}

export interface ModelRegistry {
  list(): readonly RegisteredModel[];
  get(id: string): RegisteredModel | undefined;
  /** Like `get`, but throws for a model that is not registered. */
  require(id: string): RegisteredModel;
  /**
   * The hosts to allow for guard dog egress: those of the given models, or of
   * every registered model. Sorted, without duplicates.
   */
  egressHosts(ids?: Iterable<string>): string[];
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$/;
const MAX_INPUT_LIMIT = 1_000_000;

function checkName(value: unknown, label: string): string {
  if (typeof value !== 'string' || !NAME.test(value)) {
    throw new RangeError(`${label} must be 1 to 100 letters, digits or . _ : / - and start with a letter or digit`);
  }
  return value;
}

/**
 * Check an endpoint and return it in canonical form with its host. The
 * canonical form is what the dog will call, so the host on the egress
 * allow-list and the host actually contacted cannot differ because two URL
 * parsers read an odd string differently.
 */
function checkEndpoint(endpoint: unknown, id: string): { endpoint: string; host: string } {
  if (typeof endpoint !== 'string') throw new RangeError(`${id}: the endpoint must be a URL`);
  // Only https, and nothing odd: backslashes, whitespace, control characters and extra slashes are read differently by different URL parsers.
  if (/[\s\\\u0000-\u001f\u007f]/.test(endpoint) || !/^https:\/\/[^/\\@?#]/.test(endpoint)) {
    throw new RangeError(`${id}: the endpoint must be a plain https URL such as https://host/path`);
  }
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new RangeError(`${id}: the endpoint is not a valid URL`);
  }
  if (url.username !== '' || url.password !== '') {
    throw new RangeError(`${id}: the endpoint must not contain credentials`);
  }
  if (url.search !== '' || url.hash !== '') {
    throw new RangeError(`${id}: the endpoint must not have a query string or fragment, which is where keys end up in logs`);
  }
  const host = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (host.length === 0) throw new RangeError(`${id}: the endpoint has no host`);
  if (isIP(host) !== 0) {
    throw new RangeError(`${id}: use a host name, not an IP address: certificates are checked by name, and a raw IP is what the egress rule treats as suspicious`);
  }
  url.hostname = host;
  return { endpoint: url.href, host };
}

/** Validate the models once, up front, and freeze the result. */
export function createModelRegistry(specs: readonly ModelSpec[]): ModelRegistry {
  if (specs.length === 0) throw new RangeError('register at least one model');

  const models = new Map<string, RegisteredModel>();
  for (const spec of specs) {
    const id = checkName(spec.id, 'a model id');
    if (models.has(id)) throw new RangeError(`duplicate model "${id}"`);
    const provider = checkName(spec.provider, `${id}: provider`);
    const family = checkName(spec.family, `${id}: family`);
    if (spec.tier !== 'small' && spec.tier !== 'large') throw new RangeError(`${id}: tier must be "small" or "large"`);
    if (!Object.hasOwn(HANDLING_RANK, spec.handling)) {
      throw new RangeError(`${id}: handling must be one of ${Object.keys(HANDLING_RANK).join(', ')}`);
    }
    if (!Number.isInteger(spec.maxInputChars) || spec.maxInputChars < 1 || spec.maxInputChars > MAX_INPUT_LIMIT) {
      throw new RangeError(`${id}: maxInputChars must be a whole number from 1 to ${MAX_INPUT_LIMIT}`);
    }
    const { endpoint, host } = checkEndpoint(spec.endpoint, id);
    models.set(id, Object.freeze({ id, provider, family, tier: spec.tier, endpoint, handling: spec.handling, maxInputChars: spec.maxInputChars, host }));
  }

  const ordered = Object.freeze([...models.values()]);
  const require = (id: string): RegisteredModel => {
    const model = models.get(id);
    if (model === undefined) throw new RangeError(`model "${id}" is not in the registry`);
    return model;
  };

  return {
    list: () => ordered,
    get: (id) => models.get(id),
    require,
    egressHosts(ids) {
      const chosen = ids === undefined ? ordered : [...ids].map(require);
      return [...new Set(chosen.map((model) => model.host))].sort();
    },
  };
}

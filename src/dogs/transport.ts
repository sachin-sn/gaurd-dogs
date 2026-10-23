/**
 * The one way a guard dog talks to a model API: a single JSON POST to a URL
 * that came from the model registry.
 *
 * Everything here assumes the other end can misbehave and that the text going
 * out may be sensitive:
 *
 * - The URL is passed in by the caller from the registry. This module never
 *   builds one, so nothing in the evidence can steer a request to another host.
 * - Redirects are refused. A redirect would carry the API key and the evidence
 *   to a host nobody put on the egress allow-list.
 * - The wait is bounded by the panel's abort signal and by its own timeout, and
 *   the answer is read with a size cap, so a hostile or broken server cannot
 *   hold a dog open or fill its memory.
 * - An error never includes the response body, the headers or the underlying
 *   error's message. Model API errors can quote the request, and a request holds
 *   the evidence. Only the kind of failure and an HTTP status number survive.
 */

export type ModelErrorKind = 'config' | 'input' | 'network' | 'http' | 'response' | 'refused' | 'output';

const ERROR_NAMES: Readonly<Record<ModelErrorKind, string>> = {
  config: 'ModelConfigError',
  input: 'ModelInputError',
  network: 'ModelNetworkError',
  http: 'ModelHttpError',
  response: 'ModelResponseError',
  refused: 'ModelRefusedError',
  output: 'ModelOutputError',
};

/**
 * Why a model call produced no usable answer. The panel records only `name`,
 * so each kind has its own name: that is what shows up in the audit trail.
 */
export class ModelError extends Error {
  readonly kind: ModelErrorKind;
  /** The HTTP status, for `http` errors. */
  readonly status?: number;

  constructor(kind: ModelErrorKind, message: string, status?: number) {
    super(message);
    this.name = ERROR_NAMES[kind];
    this.kind = kind;
    if (status !== undefined) this.status = status;
  }
}

export interface TransportOptions {
  /** For tests, or to route through a proxy. Default: the global `fetch`. */
  fetch?: typeof fetch;
  /** Longest one call may take, in milliseconds. Default 30,000. */
  timeoutMs?: number;
  /** Largest answer accepted, in bytes. Default 262,144. */
  maxResponseBytes?: number;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 300_000;
const DEFAULT_MAX_RESPONSE_BYTES = 262_144;
const MAX_RESPONSE_LIMIT = 4_194_304;

export function checkTransportOptions(options: TransportOptions): { timeoutMs: number; maxResponseBytes: number } {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new RangeError(`timeoutMs must be a whole number from 1 to ${MAX_TIMEOUT_MS}`);
  }
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  if (!Number.isInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > MAX_RESPONSE_LIMIT) {
    throw new RangeError(`maxResponseBytes must be a whole number from 1 to ${MAX_RESPONSE_LIMIT}`);
  }
  return { timeoutMs, maxResponseBytes };
}

/** POST `body` as JSON to `url` and return the parsed JSON answer. */
export async function postJson(
  url: string,
  headers: Readonly<Record<string, string>>,
  body: unknown,
  signal: AbortSignal,
  options: TransportOptions,
): Promise<unknown> {
  const { timeoutMs, maxResponseBytes } = checkTransportOptions(options);
  const send = options.fetch ?? globalThis.fetch;

  let response: Response;
  try {
    response = await send(url, {
      method: 'POST',
      // Ours go last, so a caller's header cannot change the content type.
      headers: { ...headers, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]),
    });
  } catch {
    // The underlying message can name the URL or quote the request: say nothing of it.
    throw new ModelError('network', signal.aborted ? 'the call was cancelled' : 'the call failed or timed out');
  }

  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new ModelError('http', `the model API answered HTTP ${response.status}`, response.status);
  }
  if (!/json/i.test(response.headers.get('content-type') ?? '')) {
    await response.body?.cancel().catch(() => undefined);
    throw new ModelError('response', 'the model API did not answer with JSON');
  }

  const text = await readCapped(response, maxResponseBytes);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ModelError('response', 'the model API answer was not valid JSON');
  }
}

async function readCapped(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (reader === undefined) throw new ModelError('response', 'the model API sent no body');
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new ModelError('response', 'the model API answer was larger than the limit');
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof ModelError) throw error;
    throw new ModelError('network', 'the answer could not be read to the end');
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new ModelError('response', 'the model API answer was not valid UTF-8');
  }
}

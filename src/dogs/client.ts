/**
 * A model client: one registered model, one API protocol, one key.
 *
 * `createModelClient` takes the registry and a model *id*, not a URL. The only
 * endpoint a client can ever call is the one the registry holds for that id, so
 * a dog has no way to be pointed anywhere else, by configuration drift, by a
 * model's output or by the evidence.
 *
 * The library never reads the environment. The deployer passes keys in, and a
 * key is only ever placed in a request header: it is not stored on the client
 * object, not logged and not part of any error.
 */

import type { ModelRegistry, RegisteredModel } from '../models/registry.js';
import {
  MODEL_PROTOCOLS,
  buildRequest,
  readAnswer,
  type ModelProtocol,
  type ModelRequest,
  type ResolvedBinding,
} from './protocols.js';
import { ModelError, checkTransportOptions, postJson, type TransportOptions } from './transport.js';

/** How to talk to one registered model. */
export interface ModelBinding {
  protocol: ModelProtocol;
  /**
   * The provider's own name for the model, for `anthropic` and
   * `openai-compatible`. Not allowed for `gemini`, which names the model in the
   * endpoint path that the registry already holds.
   */
  apiModel?: string;
  /** The API key, or a function that returns it (called for every request, so it can be rotated). */
  apiKey: string | (() => string | Promise<string>);
  /** The most tokens a reply may use. A vote is short. Default 400. */
  maxOutputTokens?: number;
  /** `openai-compatible` only: some servers want `max_tokens`. Default `max_completion_tokens`. */
  maxTokensField?: 'max_tokens' | 'max_completion_tokens';
  /** `anthropic` only. Default `2023-06-01`. */
  anthropicVersion?: string;
}

export interface ModelClient {
  /** The registered model this client calls. */
  readonly model: RegisteredModel;
  /** Send one request and return the text the model wrote. Throws `ModelError`. */
  complete(request: ModelRequest, signal: AbortSignal): Promise<string>;
}

const API_MODEL = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$/;
const API_VERSION = /^\d{4}-\d{2}-\d{2}$/;
// Printable ASCII, no spaces: nothing that could end a header line.
const API_KEY = /^[\x21-\x7e]{1,512}$/;
const DEFAULT_MAX_OUTPUT_TOKENS = 400;

function resolveBinding(model: RegisteredModel, binding: ModelBinding): ResolvedBinding {
  const id = model.id;
  if (!MODEL_PROTOCOLS.includes(binding.protocol)) {
    throw new RangeError(`${id}: protocol must be one of ${MODEL_PROTOCOLS.join(', ')}`);
  }
  const resolved: ResolvedBinding = {
    protocol: binding.protocol,
    maxOutputTokens: binding.maxOutputTokens ?? DEFAULT_MAX_OUTPUT_TOKENS,
    maxTokensField: binding.maxTokensField ?? 'max_completion_tokens',
    anthropicVersion: binding.anthropicVersion ?? '2023-06-01',
  };
  if (!Number.isInteger(resolved.maxOutputTokens) || resolved.maxOutputTokens < 16 || resolved.maxOutputTokens > 4096) {
    throw new RangeError(`${id}: maxOutputTokens must be a whole number from 16 to 4096`);
  }
  if (resolved.maxTokensField !== 'max_tokens' && resolved.maxTokensField !== 'max_completion_tokens') {
    throw new RangeError(`${id}: maxTokensField must be max_tokens or max_completion_tokens`);
  }
  if (binding.maxTokensField !== undefined && binding.protocol !== 'openai-compatible') {
    throw new RangeError(`${id}: maxTokensField only applies to the openai-compatible protocol`);
  }
  if (binding.anthropicVersion !== undefined && binding.protocol !== 'anthropic') {
    throw new RangeError(`${id}: anthropicVersion only applies to the anthropic protocol`);
  }
  if (!API_VERSION.test(resolved.anthropicVersion)) {
    throw new RangeError(`${id}: anthropicVersion must look like 2023-06-01`);
  }
  if (binding.protocol === 'gemini') {
    if (binding.apiModel !== undefined) {
      throw new RangeError(`${id}: with gemini the model is in the endpoint path, so leave apiModel out`);
    }
  } else {
    if (typeof binding.apiModel !== 'string' || !API_MODEL.test(binding.apiModel)) {
      throw new RangeError(`${id}: apiModel is the provider's name for the model: 1 to 100 letters, digits or . _ : / -`);
    }
    resolved.apiModel = binding.apiModel;
  }
  if (typeof binding.apiKey !== 'string' && typeof binding.apiKey !== 'function') {
    throw new RangeError(`${id}: apiKey must be a string or a function that returns one`);
  }
  return resolved;
}

export function createModelClient(
  registry: ModelRegistry,
  modelId: string,
  binding: ModelBinding,
  options: TransportOptions = {},
): ModelClient {
  const model = registry.require(modelId);
  const resolved = resolveBinding(model, binding);
  checkTransportOptions(options);
  const { apiKey } = binding;

  return Object.freeze({
    model,
    async complete(request: ModelRequest, signal: AbortSignal): Promise<string> {
      let key: unknown;
      try {
        key = typeof apiKey === 'function' ? await apiKey() : apiKey;
      } catch {
        // Whatever the key function threw may contain the key.
        throw new ModelError('config', 'the API key could not be read');
      }
      if (typeof key !== 'string' || !API_KEY.test(key)) {
        throw new ModelError('config', 'the API key is missing or has characters a header cannot hold');
      }
      const { headers, body } = buildRequest(resolved, request, key);
      // The URL is the registry's, as validated and canonicalised there.
      const json = await postJson(model.endpoint, headers, body, signal, options);
      return readAnswer(resolved.protocol, json);
    },
  });
}

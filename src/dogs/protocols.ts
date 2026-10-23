/**
 * The wire formats of the three kinds of model API a dog can use. Each one is
 * a pair of pure functions: build the request, and read the answer down to the
 * plain text the model wrote.
 *
 * Reading is strict about *why* the model stopped. A reply that was cut off, or
 * that the provider filtered or refused, is never turned into a vote, because a
 * truncated `{"decision":"appro` must not be repaired into anything.
 *
 * These follow each provider's documented request shape. They have been tested
 * against recorded-shape fakes, not against the live services.
 */

import { ModelError } from './transport.js';

export type ModelProtocol = 'anthropic' | 'gemini' | 'openai-compatible';

export const MODEL_PROTOCOLS: readonly ModelProtocol[] = ['anthropic', 'gemini', 'openai-compatible'];

/** What a dog says to a model: fixed instructions, and one message holding the case. */
export interface ModelRequest {
  system: string;
  user: string;
}

/** Settings after validation, so the builders can rely on them. */
export interface ResolvedBinding {
  protocol: ModelProtocol;
  /** The provider's name for the model, for protocols that name it in the body. */
  apiModel?: string;
  maxOutputTokens: number;
  maxTokensField: 'max_tokens' | 'max_completion_tokens';
  anthropicVersion: string;
}

export interface BuiltRequest {
  headers: Record<string, string>;
  body: unknown;
}

type Obj = Record<string, unknown>;

const isObj = (value: unknown): value is Obj => typeof value === 'object' && value !== null && !Array.isArray(value);

export function buildRequest(binding: ResolvedBinding, request: ModelRequest, key: string): BuiltRequest {
  switch (binding.protocol) {
    case 'anthropic':
      return {
        headers: { 'x-api-key': key, 'anthropic-version': binding.anthropicVersion },
        // No temperature or other sampling settings: newer models refuse them.
        body: {
          model: binding.apiModel,
          max_tokens: binding.maxOutputTokens,
          system: request.system,
          messages: [{ role: 'user', content: request.user }],
        },
      };
    case 'gemini':
      // The model is part of the registered endpoint's path, so it is not repeated here.
      return {
        headers: { 'x-goog-api-key': key },
        body: {
          systemInstruction: { parts: [{ text: request.system }] },
          contents: [{ role: 'user', parts: [{ text: request.user }] }],
          generationConfig: { maxOutputTokens: binding.maxOutputTokens, responseMimeType: 'application/json' },
        },
      };
    case 'openai-compatible':
      return {
        headers: { authorization: `Bearer ${key}` },
        body: {
          model: binding.apiModel,
          messages: [
            { role: 'system', content: request.system },
            { role: 'user', content: request.user },
          ],
          [binding.maxTokensField]: binding.maxOutputTokens,
        },
      };
  }
}

/** The text the model wrote, or a `ModelError` saying it did not finish or would not answer. */
export function readAnswer(protocol: ModelProtocol, json: unknown): string {
  if (!isObj(json)) throw new ModelError('response', 'the model API answer was not an object');
  switch (protocol) {
    case 'anthropic':
      return readAnthropic(json);
    case 'gemini':
      return readGemini(json);
    case 'openai-compatible':
      return readOpenAi(json);
  }
}

function readAnthropic(json: Obj): string {
  const stop = json['stop_reason'];
  if (stop === 'refusal') throw new ModelError('refused', 'the model declined to answer');
  if (stop !== 'end_turn' && stop !== 'stop_sequence') {
    throw new ModelError('output', 'the model did not finish its answer');
  }
  const content = json['content'];
  if (!Array.isArray(content)) throw new ModelError('response', 'the answer has no content');
  const text = content
    .filter((block): block is Obj => isObj(block) && block['type'] === 'text' && typeof block['text'] === 'string')
    .map((block) => block['text'] as string)
    .join('');
  if (text.length === 0) throw new ModelError('output', 'the model wrote no text');
  return text;
}

const GEMINI_DECLINED = new Set(['SAFETY', 'PROHIBITED_CONTENT', 'BLOCKLIST', 'SPII', 'RECITATION', 'IMAGE_SAFETY']);

function readGemini(json: Obj): string {
  const feedback = json['promptFeedback'];
  if (isObj(feedback) && feedback['blockReason'] !== undefined) {
    throw new ModelError('refused', 'the provider blocked the request');
  }
  const candidates = json['candidates'];
  const first: unknown = Array.isArray(candidates) ? candidates[0] : undefined;
  if (!isObj(first)) throw new ModelError('response', 'the answer has no candidate');
  const finish = first['finishReason'];
  if (typeof finish === 'string' && GEMINI_DECLINED.has(finish)) {
    throw new ModelError('refused', 'the provider declined to answer');
  }
  if (finish !== 'STOP') throw new ModelError('output', 'the model did not finish its answer');
  const content = first['content'];
  const parts: unknown = isObj(content) ? content['parts'] : undefined;
  if (!Array.isArray(parts)) throw new ModelError('response', 'the candidate has no parts');
  const text = parts
    // Thinking models label their notes; only the answer counts.
    .filter((part): part is Obj => isObj(part) && typeof part['text'] === 'string' && part['thought'] !== true)
    .map((part) => part['text'] as string)
    .join('');
  if (text.length === 0) throw new ModelError('output', 'the model wrote no text');
  return text;
}

function readOpenAi(json: Obj): string {
  const choices = json['choices'];
  const first: unknown = Array.isArray(choices) ? choices[0] : undefined;
  if (!isObj(first)) throw new ModelError('response', 'the answer has no choice');
  const finish = first['finish_reason'];
  if (finish === 'content_filter') throw new ModelError('refused', 'the provider filtered the answer');
  const message = first['message'];
  if (!isObj(message)) throw new ModelError('response', 'the choice has no message');
  if (typeof message['refusal'] === 'string' && message['refusal'].length > 0) {
    throw new ModelError('refused', 'the model declined to answer');
  }
  if (finish !== 'stop') throw new ModelError('output', 'the model did not finish its answer');
  const content = message['content'];
  if (typeof content !== 'string' || content.length === 0) throw new ModelError('output', 'the model wrote no text');
  return content;
}

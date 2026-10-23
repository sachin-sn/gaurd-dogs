import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import {
  ModelError,
  buildRequest,
  createModelClient,
  createModelRegistry,
  postJson,
  readAnswer,
  type ModelBinding,
  type ModelProtocol,
  type ResolvedBinding,
} from '../src/index.js';

const SECRET = 'KEY-secret-0123456789';
const CLAUDE_URL = 'https://api.anthropic.example.invalid/v1/messages';
const GEMINI_URL = 'https://generativelanguage.example.invalid/v1beta/models/gemini-large:generateContent';
const LOCAL_URL = 'https://llm.internal.example.invalid/v1/chat/completions';

const registry = createModelRegistry([
  { id: 'claude-large', provider: 'anthropic', family: 'claude', tier: 'large', endpoint: CLAUDE_URL, handling: 'zero-retention', maxInputChars: 20_000 },
  { id: 'gemini-large', provider: 'google', family: 'gemini', tier: 'large', endpoint: GEMINI_URL, handling: 'zero-retention', maxInputChars: 20_000 },
  { id: 'local-large', provider: 'selfhosted', family: 'open', tier: 'large', endpoint: LOCAL_URL, handling: 'self-hosted', maxInputChars: 20_000 },
]);

const bindings = {
  'claude-large': { protocol: 'anthropic', apiModel: 'claude-sonnet-5-5', apiKey: SECRET },
  'gemini-large': { protocol: 'gemini', apiKey: SECRET },
  'local-large': { protocol: 'openai-compatible', apiModel: 'open-model-1', apiKey: SECRET },
} satisfies Record<string, ModelBinding>;

const jsonResponse = (value: unknown, init: ResponseInit = {}): Response =>
  new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' }, ...init });

interface Call {
  url: string;
  init: RequestInit;
  body: Record<string, unknown>;
}
function fakeFetch(handler: (call: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  const fn = (async (url: string | URL | Request, init?: RequestInit) => {
    const call: Call = { url: String(url), init: init as RequestInit, body: JSON.parse((init as RequestInit).body as string) as Record<string, unknown> };
    calls.push(call);
    return handler(call);
  }) as typeof fetch;
  return { fn, calls };
}
const headersOf = (call: Call): Record<string, string> => call.init.headers as Record<string, string>;
const never = new AbortController().signal;

const anthropicReply = (text: string, stop: string = 'end_turn') => ({ type: 'message', role: 'assistant', content: [{ type: 'text', text }], stop_reason: stop });
const geminiReply = (text: string, finish: string = 'STOP') => ({ candidates: [{ content: { role: 'model', parts: [{ text }] }, finishReason: finish }] });
const openAiReply = (text: string | null, finish: string = 'stop') => ({ choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: finish }] });

const REQUEST = { system: 'SYS', user: 'USER' };
const resolved = (protocol: ModelProtocol, extra: Partial<ResolvedBinding> = {}): ResolvedBinding => ({
  protocol,
  maxOutputTokens: 400,
  maxTokensField: 'max_completion_tokens',
  anthropicVersion: '2023-06-01',
  ...(protocol === 'gemini' ? {} : { apiModel: 'm-1' }),
  ...extra,
});

describe('postJson, against a fake fetch', () => {
  it('posts JSON to exactly the URL it was given and refuses redirects', async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ ok: true }));
    const result = await postJson('https://a.example.invalid/x', { 'x-api-key': 'k', 'content-type': 'text/plain' }, { a: 1 }, never, { fetch: fn });

    expect(result).toEqual({ ok: true });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('https://a.example.invalid/x');
    expect(calls[0]?.init.method).toBe('POST');
    expect(calls[0]?.init.redirect).toBe('error');
    expect(calls[0]?.body).toEqual({ a: 1 });
    // A caller's header cannot change what we say the body is.
    expect(headersOf(calls[0] as Call)).toMatchObject({ 'x-api-key': 'k', 'content-type': 'application/json', accept: 'application/json' });
  });

  it('passes the caller\'s abort on to the request', async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({}));
    const controller = new AbortController();
    await postJson('https://a.example.invalid/x', {}, {}, controller.signal, { fetch: fn });
    const sent = calls[0]?.init.signal as AbortSignal;
    expect(sent.aborted).toBe(false);
    controller.abort();
    expect(sent.aborted).toBe(true);
  });

  it('turns an HTTP error into a status number and nothing else', async () => {
    const leak = `quoting your request: Authorization ${SECRET} and the evidence hunter2`;
    const { fn } = fakeFetch(() => new Response(leak, { status: 429, statusText: leak, headers: { 'content-type': 'text/plain' } }));
    const error = await postJson('https://a.example.invalid/x', {}, {}, never, { fetch: fn }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ModelError);
    expect(error).toMatchObject({ kind: 'http', status: 429, name: 'ModelHttpError' });
    expect(JSON.stringify(error)).not.toContain(SECRET);
    expect((error as Error).message).not.toMatch(/hunter2|Authorization|quoting/);
  });

  it('wraps a failing fetch without keeping its message', async () => {
    const failing = (async () => {
      throw new Error(`connect failed to https://a.example.invalid/x?key=${SECRET}`);
    }) as typeof fetch;
    const error = (await postJson('https://a.example.invalid/x', {}, {}, never, { fetch: failing }).catch((e: unknown) => e)) as ModelError;

    expect(error).toMatchObject({ kind: 'network', name: 'ModelNetworkError' });
    expect(error.message).not.toContain(SECRET);
    expect(error.cause).toBeUndefined();
  });

  it('says a call was cancelled when the caller aborted', async () => {
    const controller = new AbortController();
    const waiting = (async (_url: unknown, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
      })) as typeof fetch;
    const pending = postJson('https://a.example.invalid/x', {}, {}, controller.signal, { fetch: waiting }).catch((e: unknown) => e);
    controller.abort();
    expect(await pending).toMatchObject({ kind: 'network', message: 'the call was cancelled' });
  });

  it('refuses an answer that is not JSON, or not valid JSON, or not valid UTF-8', async () => {
    const answer = async (response: Response) => {
      const { fn } = fakeFetch(() => response);
      return (await postJson('https://a.example.invalid/x', {}, {}, never, { fetch: fn }).catch((e: unknown) => e)) as ModelError;
    };
    expect(await answer(new Response('<html>', { headers: { 'content-type': 'text/html' } }))).toMatchObject({ kind: 'response' });
    expect(await answer(new Response('{"a":', { headers: { 'content-type': 'application/json' } }))).toMatchObject({ kind: 'response' });
    expect(await answer(new Response(new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]), { headers: { 'content-type': 'application/json' } }))).toMatchObject({
      kind: 'response',
      message: expect.stringMatching(/UTF-8/) as unknown as string,
    });
  });

  it('checks its limits', async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    for (const timeoutMs of [0, -1, 1.5, 300_001, Number.NaN]) {
      await expect(postJson('https://a.example.invalid/x', {}, {}, never, { fetch: fn, timeoutMs })).rejects.toThrow(/timeoutMs/);
    }
    for (const maxResponseBytes of [0, -1, 1.5, 4_194_305]) {
      await expect(postJson('https://a.example.invalid/x', {}, {}, never, { fetch: fn, maxResponseBytes })).rejects.toThrow(/maxResponseBytes/);
    }
  });
});

describe('postJson, against a real local server', () => {
  const servers: http.Server[] = [];
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); })));
  });
  async function serve(handler: http.RequestListener): Promise<string> {
    const server = http.createServer(handler);
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  }

  it('does not follow a redirect, so the key and evidence cannot be carried to another host', async () => {
    let elsewhere = 0;
    const target = await serve((_req, res) => {
      elsewhere++;
      res.setHeader('content-type', 'application/json').end('{"leaked":true}');
    });
    const start = await serve((_req, res) => {
      res.statusCode = 302;
      res.setHeader('location', target).end();
    });

    const error = (await postJson(start, { 'x-api-key': SECRET }, { evidence: 'hunter2' }, never, {}).catch((e: unknown) => e)) as ModelError;
    expect(error).toBeInstanceOf(ModelError);
    expect(error.kind).toBe('network');
    expect(elsewhere).toBe(0);
  });

  it('stops reading an answer that is larger than the limit', async () => {
    const url = await serve((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.write('{"text":"');
      const chunk = 'a'.repeat(10_000);
      const timer = setInterval(() => res.write(chunk), 1);
      res.on('close', () => clearInterval(timer));
    });
    const error = (await postJson(url, {}, {}, never, { maxResponseBytes: 50_000 }).catch((e: unknown) => e)) as ModelError;
    expect(error).toMatchObject({ kind: 'response', message: 'the model API answer was larger than the limit' });
  });

  it('gives up on a server that never answers', async () => {
    const url = await serve(() => undefined);
    const error = (await postJson(url, {}, {}, never, { timeoutMs: 80 }).catch((e: unknown) => e)) as ModelError;
    expect(error).toMatchObject({ kind: 'network', message: 'the call failed or timed out' });
  });

  it('reads a normal answer', async () => {
    const url = await serve((_req, res) => {
      res.setHeader('content-type', 'application/json; charset=utf-8').end('{"ok":"é"}');
    });
    expect(await postJson(url, {}, {}, never, {})).toEqual({ ok: 'é' });
  });
});

describe('request shapes', () => {
  it('anthropic: model and system in the body, key and version in headers, no sampling settings', () => {
    const built = buildRequest(resolved('anthropic', { apiModel: 'claude-sonnet-5-5' }), REQUEST, 'K');
    expect(built.headers).toEqual({ 'x-api-key': 'K', 'anthropic-version': '2023-06-01' });
    expect(built.body).toEqual({
      model: 'claude-sonnet-5-5',
      max_tokens: 400,
      system: 'SYS',
      messages: [{ role: 'user', content: 'USER' }],
    });
    expect(Object.keys(built.body as object)).not.toContain('temperature');
  });

  it('gemini: key in a header (never the URL), model not in the body, JSON mime type', () => {
    const built = buildRequest(resolved('gemini'), REQUEST, 'K');
    expect(built.headers).toEqual({ 'x-goog-api-key': 'K' });
    expect(built.body).toEqual({
      systemInstruction: { parts: [{ text: 'SYS' }] },
      contents: [{ role: 'user', parts: [{ text: 'USER' }] }],
      generationConfig: { maxOutputTokens: 400, responseMimeType: 'application/json' },
    });
  });

  it('openai-compatible: bearer key, system message first, token field by setting', () => {
    const built = buildRequest(resolved('openai-compatible'), REQUEST, 'K');
    expect(built.headers).toEqual({ authorization: 'Bearer K' });
    expect(built.body).toEqual({
      model: 'm-1',
      messages: [
        { role: 'system', content: 'SYS' },
        { role: 'user', content: 'USER' },
      ],
      max_completion_tokens: 400,
    });
    const older = buildRequest(resolved('openai-compatible', { maxTokensField: 'max_tokens' }), REQUEST, 'K').body as Record<string, unknown>;
    expect(older['max_tokens']).toBe(400);
    expect(older).not.toHaveProperty('max_completion_tokens');
  });
});

describe('reading answers', () => {
  const kindOf = (protocol: ModelProtocol, json: unknown): string => {
    try {
      readAnswer(protocol, json);
    } catch (error) {
      return (error as ModelError).kind;
    }
    return 'none';
  };

  it('anthropic: joins the text blocks, ignores the rest, and wants a finished answer', () => {
    expect(readAnswer('anthropic', anthropicReply('hello'))).toBe('hello');
    expect(
      readAnswer('anthropic', {
        stop_reason: 'end_turn',
        content: [{ type: 'thinking', thinking: 'secret notes' }, { type: 'text', text: 'a' }, { type: 'text', text: 'b' }],
      }),
    ).toBe('ab');
    expect(readAnswer('anthropic', anthropicReply('x', 'stop_sequence'))).toBe('x');

    expect(kindOf('anthropic', anthropicReply('x', 'refusal'))).toBe('refused');
    for (const stop of ['max_tokens', 'tool_use', 'pause_turn', 'model_context_window_exceeded', 'something-new']) {
      expect(kindOf('anthropic', anthropicReply('{"decision":"appro', stop))).toBe('output');
    }
    expect(kindOf('anthropic', { stop_reason: 'end_turn' })).toBe('response');
    expect(kindOf('anthropic', { stop_reason: 'end_turn', content: [] })).toBe('output');
    expect(kindOf('anthropic', { stop_reason: 'end_turn', content: [{ type: 'thinking', thinking: 't' }] })).toBe('output');
    expect(kindOf('anthropic', {})).toBe('output');
  });

  it('gemini: skips thought parts and wants STOP', () => {
    expect(readAnswer('gemini', geminiReply('hello'))).toBe('hello');
    expect(
      readAnswer('gemini', { candidates: [{ finishReason: 'STOP', content: { parts: [{ text: 'my notes', thought: true }, { text: 'a' }, { text: 'b' }] } }] }),
    ).toBe('ab');

    expect(kindOf('gemini', { promptFeedback: { blockReason: 'SAFETY' }, candidates: [] })).toBe('refused');
    for (const finish of ['SAFETY', 'PROHIBITED_CONTENT', 'BLOCKLIST', 'SPII', 'RECITATION', 'IMAGE_SAFETY']) {
      expect(kindOf('gemini', geminiReply('x', finish))).toBe('refused');
    }
    for (const finish of ['MAX_TOKENS', 'OTHER', 'something-new']) expect(kindOf('gemini', geminiReply('x', finish))).toBe('output');
    expect(kindOf('gemini', { candidates: [{ content: { parts: [{ text: '{}' }] } }] })).toBe('output');
    expect(kindOf('gemini', { candidates: [] })).toBe('response');
    expect(kindOf('gemini', { candidates: [{ finishReason: 'STOP' }] })).toBe('response');
    expect(kindOf('gemini', geminiReply(''))).toBe('output');
  });

  it('openai-compatible: wants a finished string, and reports refusals and filters', () => {
    expect(readAnswer('openai-compatible', openAiReply('hello'))).toBe('hello');

    expect(kindOf('openai-compatible', openAiReply('x', 'content_filter'))).toBe('refused');
    expect(kindOf('openai-compatible', { choices: [{ finish_reason: 'stop', message: { content: null, refusal: 'no' } }] })).toBe('refused');
    expect(kindOf('openai-compatible', openAiReply('{"decision":"appro', 'length'))).toBe('output');
    expect(kindOf('openai-compatible', openAiReply(null))).toBe('output');
    expect(kindOf('openai-compatible', openAiReply(''))).toBe('output');
    expect(kindOf('openai-compatible', { choices: [] })).toBe('response');
    expect(kindOf('openai-compatible', { choices: [{ finish_reason: 'stop' }] })).toBe('response');
  });

  it('refuses an answer that is not an object', () => {
    for (const protocol of ['anthropic', 'gemini', 'openai-compatible'] as const) {
      for (const value of [null, 'text', 3, [1], undefined]) expect(kindOf(protocol, value)).toBe('response');
    }
  });
});

describe('createModelClient', () => {
  it('calls the registry\'s endpoint and nothing else, for every protocol', async () => {
    const replies: Record<string, unknown> = {
      [CLAUDE_URL]: anthropicReply('A'),
      [GEMINI_URL]: geminiReply('G'),
      [LOCAL_URL]: openAiReply('L'),
    };
    const { fn, calls } = fakeFetch((call) => jsonResponse(replies[call.url]));

    const out: string[] = [];
    for (const id of ['claude-large', 'gemini-large', 'local-large'] as const) {
      const client = createModelClient(registry, id, bindings[id], { fetch: fn });
      expect(client.model).toBe(registry.require(id));
      out.push(await client.complete(REQUEST, never));
    }
    expect(out).toEqual(['A', 'G', 'L']);
    expect(calls.map((call) => call.url)).toEqual([CLAUDE_URL, GEMINI_URL, LOCAL_URL]);
    // The registry's canonical form: the Gemini path keeps its colon.
    expect(registry.require('gemini-large').endpoint).toBe(GEMINI_URL);
    expect(calls[0]?.body['model']).toBe('claude-sonnet-5-5');
    expect(calls[2]?.body['model']).toBe('open-model-1');
    expect(calls[1]?.body).not.toHaveProperty('model');
  });

  it('can only be made for a registered model', () => {
    expect(() => createModelClient(registry, 'nope', bindings['claude-large'])).toThrow(/not in the registry/);
    expect(() => createModelClient(registry, 'constructor', bindings['claude-large'])).toThrow(/not in the registry/);
  });

  it('checks the binding when it is made, not on the first incident', () => {
    const make = (binding: Partial<ModelBinding> & { protocol: ModelProtocol }, id = 'claude-large') =>
      createModelClient(registry, id, { apiKey: SECRET, ...binding } as ModelBinding);

    expect(() => make({ protocol: 'carrier-pigeon' as ModelProtocol })).toThrow(/protocol must be one of/);
    expect(() => make({ protocol: 'anthropic' })).toThrow(/apiModel is the provider's name/);
    expect(() => make({ protocol: 'anthropic', apiModel: 'has space' })).toThrow(/apiModel/);
    expect(() => make({ protocol: 'openai-compatible', apiModel: '' })).toThrow(/apiModel/);
    expect(() => make({ protocol: 'gemini', apiModel: 'gemini-large' }, 'gemini-large')).toThrow(/endpoint path/);
    for (const maxOutputTokens of [0, 15, 4097, 1.5, Number.NaN]) {
      expect(() => make({ protocol: 'anthropic', apiModel: 'm', maxOutputTokens })).toThrow(/maxOutputTokens/);
    }
    expect(() => make({ protocol: 'anthropic', apiModel: 'm', maxTokensField: 'max_tokens' })).toThrow(/openai-compatible/);
    expect(() => make({ protocol: 'openai-compatible', apiModel: 'm', maxTokensField: 'tokens' as 'max_tokens' })).toThrow(/maxTokensField/);
    expect(() => make({ protocol: 'openai-compatible', apiModel: 'm', anthropicVersion: '2023-06-01' })).toThrow(/anthropic protocol/);
    expect(() => make({ protocol: 'anthropic', apiModel: 'm', anthropicVersion: 'latest' })).toThrow(/anthropicVersion/);
    expect(() => make({ protocol: 'anthropic', apiModel: 'm', apiKey: 5 as unknown as string })).toThrow(/apiKey/);
    expect(() => createModelClient(registry, 'claude-large', bindings['claude-large'], { timeoutMs: 0 })).toThrow(/timeoutMs/);
    expect(() => make({ protocol: 'anthropic', apiModel: 'm', anthropicVersion: '2024-01-01', maxOutputTokens: 4096 })).not.toThrow();
  });

  it('sends a rotated key on each call, and never keeps the key where it can be read back', async () => {
    let current = 'KEY-one-0000001';
    const { fn, calls } = fakeFetch(() => jsonResponse(anthropicReply('ok')));
    const client = createModelClient(registry, 'claude-large', { ...bindings['claude-large'], apiKey: () => current }, { fetch: fn });

    await client.complete(REQUEST, never);
    current = 'KEY-two-0000002';
    await client.complete(REQUEST, never);
    expect(calls.map((call) => headersOf(call)['x-api-key'])).toEqual(['KEY-one-0000001', 'KEY-two-0000002']);

    const keyed = createModelClient(registry, 'claude-large', bindings['claude-large'], { fetch: fn });
    expect(JSON.stringify(keyed)).not.toContain(SECRET);
    expect(Object.values(keyed).some((value) => value === SECRET)).toBe(false);
    expect(Object.isFrozen(keyed)).toBe(true);
  });

  it('refuses a key that is missing or could break a header, without echoing it', async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse(anthropicReply('ok')));
    for (const key of ['', 'has space', 'line\nbreak', 'tab\there', 'é-key', 'x'.repeat(513), undefined as unknown as string]) {
      const client = createModelClient(registry, 'claude-large', { ...bindings['claude-large'], apiKey: () => key }, { fetch: fn });
      const error = (await client.complete(REQUEST, never).catch((e: unknown) => e)) as ModelError;
      expect(error).toMatchObject({ kind: 'config', name: 'ModelConfigError' });
      // An empty string is "contained" in everything, so it has nothing to check.
      if (typeof key === 'string' && key.length > 0) expect(error.message).not.toContain(key);
    }
    expect(calls).toHaveLength(0);
  });

  it('does not repeat what a failing key function threw', async () => {
    const { fn } = fakeFetch(() => jsonResponse(anthropicReply('ok')));
    const client = createModelClient(
      registry,
      'claude-large',
      {
        ...bindings['claude-large'],
        apiKey: () => {
          throw new Error(`vault said no for ${SECRET}`);
        },
      },
      { fetch: fn },
    );
    const error = (await client.complete(REQUEST, never).catch((e: unknown) => e)) as ModelError;
    expect(error).toMatchObject({ kind: 'config', message: 'the API key could not be read' });
    expect(error.cause).toBeUndefined();
  });

  it('passes every failure through as a ModelError', async () => {
    const down = fakeFetch(() => new Response('overloaded', { status: 529 }));
    const client = createModelClient(registry, 'claude-large', bindings['claude-large'], { fetch: down.fn });
    expect(await client.complete(REQUEST, never).catch((e: unknown) => e)).toMatchObject({ name: 'ModelHttpError', status: 529 });

    const cut = fakeFetch(() => jsonResponse(anthropicReply('{"decision":"appro', 'max_tokens')));
    const second = createModelClient(registry, 'claude-large', bindings['claude-large'], { fetch: cut.fn });
    expect(await second.complete(REQUEST, never).catch((e: unknown) => e)).toMatchObject({ name: 'ModelOutputError' });
  });
});

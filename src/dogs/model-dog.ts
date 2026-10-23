/**
 * A guard dog that asks a model for its vote.
 *
 * Two properties the rest of the system leans on:
 *
 * - **The dog's model is the client's registered model.** `model` is read from
 *   the client, not typed in beside it. The gate's "approvals span two models"
 *   rule trusts a dog's `model` label, so a label that could differ from the
 *   model actually called would defeat that rule.
 * - **A dog never approves on evidence it could not fully see.** If the evidence
 *   was cut to fit the model's limit, an approval becomes an abstention.
 *   Missing lines may be exactly the ones that show the traffic was harmless.
 */

import type { GatePolicy } from '../gate/policy.js';
import type { ModelRegistry } from '../models/registry.js';
import type { Dog, DogOpinion, DogTask } from '../panel/panel.js';
import { createModelClient, type ModelBinding, type ModelClient } from './client.js';
import { buildVotePrompt, newNonce } from './prompt.js';
import type { TransportOptions } from './transport.js';
import { parseVerdict } from './verdict.js';

export interface ModelDogOptions {
  id: string;
  evidenceView: string;
  client: ModelClient;
  /** A fresh token for each call's block tags. Default: random. Tests pass a fixed one. */
  nonce?: () => string;
}

export class ModelDog implements Dog {
  readonly id: string;
  readonly model: string;
  readonly evidenceView: string;
  private readonly client: ModelClient;
  private readonly nonce: () => string;

  constructor(options: ModelDogOptions) {
    if (options.id.length === 0 || options.evidenceView.length === 0) {
      throw new RangeError('a dog needs an id and an evidence view');
    }
    this.id = options.id;
    this.evidenceView = options.evidenceView;
    this.client = options.client;
    this.model = options.client.model.id;
    this.nonce = options.nonce ?? newNonce;
  }

  async review(task: DogTask, signal: AbortSignal): Promise<DogOpinion> {
    const prompt = buildVotePrompt(task, this.evidenceView, this.client.model.maxInputChars, this.nonce());
    const reply = await this.client.complete(prompt.request, signal);
    const opinion = parseVerdict(reply);
    if (prompt.truncated && opinion.decision === 'approve') {
      return { decision: 'abstain', rationale: `Not approving on partial evidence. ${opinion.rationale ?? ''}`.trim() };
    }
    return opinion;
  }
}

export interface CreateDogsOptions extends TransportOptions {
  nonce?: () => string;
}

/**
 * One model-backed dog for every seat on the policy's panel, in panel order.
 * `bindings` says how to reach each model by registry id. Every problem (a
 * seat whose model is not registered, one with no binding, a binding that does
 * not fit) is found here, before anything runs, not on the first incident.
 */
export function createModelDogs(
  policy: GatePolicy,
  registry: ModelRegistry,
  bindings: Readonly<Record<string, ModelBinding>>,
  options: CreateDogsOptions = {},
): Dog[] {
  const { nonce, ...transport } = options;
  const clients = new Map<string, ModelClient>();
  const dogs: Dog[] = [];
  for (const member of policy.panel.values()) {
    if (!Object.hasOwn(bindings, member.model)) {
      throw new RangeError(`"${member.id}" uses model "${member.model}", which has no binding`);
    }
    let client = clients.get(member.model);
    if (client === undefined) {
      client = createModelClient(registry, member.model, bindings[member.model] as ModelBinding, transport);
      clients.set(member.model, client);
    }
    dogs.push(new ModelDog({ id: member.id, evidenceView: member.evidenceView, client, ...(nonce === undefined ? {} : { nonce }) }));
  }
  return dogs;
}

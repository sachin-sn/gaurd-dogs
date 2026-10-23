/**
 * Choosing which model sits behind which seat on the panel, and checking a
 * panel that someone chose by hand.
 *
 * `planPanel` spreads the seats over providers first and model families
 * second, so that:
 *
 * - the approving dogs can span two models (the gate requires it);
 * - no single provider holds a majority when the registry allows otherwise,
 *   so one provider's outage, policy change or compromise cannot approve
 *   alone or block every approval;
 * - two models of one family never sit on the same panel, because the gate
 *   counts them as different models while their blind spots are shared;
 * - a seat whose evidence view is sensitive only goes to a model whose
 *   operator handles data strongly enough.
 *
 * The plan is deterministic: the same registry and options give the same
 * panel. It is decided before anything runs, not by the dogs.
 */

import type { ActionVote } from '../core/types.js';
import { panelVerdict } from '../gate/gate.js';
import { MAX_PANEL_SIZE, type GatePolicy, type PanelMember } from '../gate/policy.js';
import { HANDLING_RANK, type ModelHandling, type ModelRegistry, type ModelTier, type RegisteredModel } from './registry.js';

export interface PlanOptions {
  /** Number of dogs: 2 to 9. */
  size: number;
  /** Which models may be used. Default 'large'. */
  tier?: ModelTier;
  /** Evidence views, handed out to the seats in turn. */
  views: readonly string[];
  /** The weakest data handling allowed for a seat that gets a given view. Default 'standard'. */
  requiredHandling?: Readonly<Record<string, ModelHandling>>;
  /** Dog ids are `<prefix>-1`, `<prefix>-2`, and so on. Default 'dog'. */
  idPrefix?: string;
}

const ID_PREFIX = /^[A-Za-z][A-Za-z0-9_-]{0,30}$/;

function handlingOk(model: RegisteredModel, minimum: ModelHandling): boolean {
  return HANDLING_RANK[model.handling] >= HANDLING_RANK[minimum];
}

export function planPanel(registry: ModelRegistry, options: PlanOptions): PanelMember[] {
  const { size } = options;
  if (!Number.isInteger(size) || size < 2 || size > MAX_PANEL_SIZE) {
    throw new RangeError(`a panel has 2 to ${MAX_PANEL_SIZE} dogs`);
  }
  const views = options.views;
  if (views.length === 0 || views.some((view) => typeof view !== 'string' || view.length === 0)) {
    throw new RangeError('give at least one evidence view, as non-empty names');
  }
  if (new Set(views).size !== views.length) throw new RangeError('evidence views must be distinct');
  const required = options.requiredHandling ?? {};
  for (const view of Object.keys(required)) {
    if (!views.includes(view)) throw new RangeError(`requiredHandling names "${view}", which is not one of the views`);
    if (!Object.hasOwn(HANDLING_RANK, required[view] as string)) throw new RangeError(`requiredHandling for "${view}" is not a handling level`);
  }
  const prefix = options.idPrefix ?? 'dog';
  if (!ID_PREFIX.test(prefix)) throw new RangeError('idPrefix must start with a letter and use letters, digits, _ or -');
  const tier = options.tier ?? 'large';

  const pool = registry.list().filter((model) => model.tier === tier);
  const seatsByProvider = new Map<string, number>();
  const seatsByFamily = new Map<string, number>();
  const modelOfFamily = new Map<string, string>();
  const members: PanelMember[] = [];

  for (let seat = 0; seat < size; seat++) {
    const view = views[seat % views.length] as string;
    const minimum = (Object.hasOwn(required, view) ? required[view] : undefined) ?? 'standard';

    // One model per family on a panel; among the rest, the least-used provider, then the least-used family.
    // Sorting is stable, so ties keep the registry's order.
    const candidates = pool
      .filter((model) => handlingOk(model, minimum) && (modelOfFamily.get(model.family) ?? model.id) === model.id)
      .map((model) => ({ model }));
    if (candidates.length === 0) {
      throw new RangeError(`no ${tier} model in the registry meets "${minimum}" handling for the "${view}" view`);
    }
    candidates.sort(
      (a, b) =>
        (seatsByProvider.get(a.model.provider) ?? 0) - (seatsByProvider.get(b.model.provider) ?? 0) ||
        (seatsByFamily.get(a.model.family) ?? 0) - (seatsByFamily.get(b.model.family) ?? 0),
    );
    const { model } = candidates[0] as { model: RegisteredModel };

    seatsByProvider.set(model.provider, (seatsByProvider.get(model.provider) ?? 0) + 1);
    seatsByFamily.set(model.family, (seatsByFamily.get(model.family) ?? 0) + 1);
    modelOfFamily.set(model.family, model.id);
    members.push({ id: `${prefix}-${seat + 1}`, model: model.id, evidenceView: view });
  }

  if (new Set(members.map((member) => member.model)).size < 2) {
    throw new RangeError(
      `the ${tier} models in the registry (after the handling limits) come from fewer than two families, so a mixed panel is not possible`,
    );
  }
  return members;
}

export interface PanelAnalysis {
  size: number;
  /** Seats per provider. */
  seatsByProvider: Readonly<Record<string, number>>;
  /** Providers whose outage leaves the other dogs unable to approve. */
  providersThatBlockApproval: string[];
  /** Providers whose dogs could approve without anyone else. */
  providersThatCanApproveAlone: string[];
  /** Groups of models on the panel that share a family: different to the gate, alike in their blind spots. */
  correlatedModels: string[][];
  /** Dogs whose model does not meet the data handling required for their view. */
  handlingViolations: string[];
  /** The above in words, for a person setting up the panel. */
  warnings: string[];
}

export interface AnalyzeOptions {
  /** The same limits `planPanel` takes, to check a panel that was built by hand. */
  requiredHandling?: Readonly<Record<string, ModelHandling>>;
}

/**
 * What a panel depends on. It asks the gate itself whether a set of approving
 * dogs would pass, so it follows the gate's majority and model-diversity rules
 * exactly. Throws if a dog uses a model that is not registered, because a model
 * outside the registry has no vetted endpoint.
 */
export function analyzePanel(registry: ModelRegistry, policy: GatePolicy, options: AnalyzeOptions = {}): PanelAnalysis {
  const specs = new Map<string, RegisteredModel>();
  for (const member of policy.panel.values()) {
    const model = registry.get(member.model);
    if (model === undefined) throw new RangeError(`"${member.id}" uses model "${member.model}", which is not in the registry`);
    specs.set(member.id, model);
  }
  const ids = [...policy.panel.keys()];
  const providerOf = (id: string): string => (specs.get(id) as RegisteredModel).provider;
  const providers = [...new Set(ids.map(providerOf))].sort();

  const wouldApprove = (approvers: ReadonlySet<string>): boolean => {
    const votes: ActionVote[] = ids.map((voter) => ({ voter, decision: approvers.has(voter) ? 'approve' : 'abstain' }));
    return panelVerdict(votes, policy).split(',').includes('info:panel-approved');
  };

  const seatsByProvider: Record<string, number> = {};
  for (const provider of providers) seatsByProvider[provider] = ids.filter((id) => providerOf(id) === provider).length;

  const providersThatBlockApproval = providers.filter(
    (provider) => !wouldApprove(new Set(ids.filter((id) => providerOf(id) !== provider))),
  );
  const providersThatCanApproveAlone = providers.filter((provider) =>
    wouldApprove(new Set(ids.filter((id) => providerOf(id) === provider))),
  );

  const byFamily = new Map<string, Set<string>>();
  for (const model of specs.values()) {
    const group = byFamily.get(model.family) ?? new Set<string>();
    group.add(model.id);
    byFamily.set(model.family, group);
  }
  const correlatedModels = [...byFamily.values()].filter((group) => group.size > 1).map((group) => [...group].sort());

  const handlingViolations: string[] = [];
  for (const member of policy.panel.values()) {
    const limits = options.requiredHandling ?? {};
    const needed = Object.hasOwn(limits, member.evidenceView) ? limits[member.evidenceView] : undefined;
    if (needed !== undefined && !handlingOk(specs.get(member.id) as RegisteredModel, needed)) handlingViolations.push(member.id);
  }

  const warnings: string[] = [];
  for (const provider of providersThatBlockApproval) {
    warnings.push(`If ${provider} is unavailable, the other dogs cannot reach a majority, so nothing is approved until a human acts.`);
  }
  for (const provider of providersThatCanApproveAlone) {
    warnings.push(`${provider}'s dogs could approve on their own: they hold a majority and use more than one model.`);
  }
  for (const group of correlatedModels) {
    warnings.push(`${group.join(' and ')} are the same family. The gate counts them as different models, but they are likely to fail together.`);
  }
  for (const id of handlingViolations) {
    warnings.push(`${id} sees a view that needs stronger data handling than its model provides.`);
  }

  return { size: ids.length, seatsByProvider, providersThatBlockApproval, providersThatCanApproveAlone, correlatedModels, handlingViolations, warnings };
}

import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type {
  PersistentApprovalApi,
  PersistentApprovalTarget,
} from "#src/persistence/persistent-approval-service";
import {
  buildDirectionalSessionLabels,
  buildForwardedScopeLabels,
  describeGrantTarget,
} from "#src/presentation/pattern-suggest";
import {
  emitUiPromptEvent,
  type PermissionEventBus,
} from "#src/service/permission-events";
import { buildUiPrompt } from "#src/service/permission-ui-prompt";
import {
  type ApprovalGrant,
  provenDirectionOf,
} from "#src/session/approval-grant";
import type { TerminalAuthorizer } from "./authorizer";
import {
  isPersistentPermissionChoice,
  type PersistentPermissionChoice,
} from "./interactive-permission-choice";
import {
  createDeniedPermissionDecision,
  type PermissionPromptDecision,
  type PersistentPromptOptions,
  type RequestPermissionOptions,
} from "./permission-dialog";
import type {
  PermissionPromptUi,
  PromptPreferences,
  requestPermissionDecision,
} from "./permission-prompt-component";
import type { PromptPermissionDetails } from "./permission-prompter";

/** Dependencies required by {@link LocalUserAuthorizer}. */
export interface LocalUserAuthorizerDeps {
  /** The active session's UI surface (select/input plus the inline `custom` dialog). */
  ui: PermissionPromptUi;
  /** The session run mode; the dispatcher renders the inline dialog only in `"tui"`. */
  mode: ExtensionContext["mode"];
  /** Event bus used for the `permissions:ui_prompt` broadcast. */
  events: PermissionEventBus;
  /** Read live at prompt time so a settings-modal toggle takes effect on the next prompt. */
  getPromptPreferences: () => PromptPreferences;
  /** Persist the sticky summary preference changed from the inline prompt. */
  setShowPersistenceSummary?: (enabled: boolean) => boolean;
  /** Injected for testability; production callers pass the real function. */
  requestPermissionDecision: typeof requestPermissionDecision;
  /** Present only for direct local sessions that may mutate durable policy. */
  persistentApprovalService?: PersistentApprovalApi;
}

/**
 * Authorizer for a session with an active UI: prompt the human here.
 *
 * Emits the `permissions:ui_prompt` broadcast (moved here from
 * `PermissionPrompter`'s `ctx.hasUI` arm) before showing the dialog, so
 * observers know a decision is imminent. This is the single emit site: a
 * forwarded ask carries its provenance on `details.forwarding`, which this
 * class renders (populated `forwarding` context + "(Subagent)" title) so the
 * broadcast stays non-degraded (#292) without a second emission path.
 *
 * It is also the only adapter from a durable choice to a decision: the write
 * happens here, and the pending call is approved only once it succeeded. A
 * failed write denies with a bounded reason, so nothing runs on a rule that
 * was never recorded.
 */
export class LocalUserAuthorizer implements TerminalAuthorizer {
  constructor(private readonly deps: LocalUserAuthorizerDeps) {}

  async authorize(
    details: PromptPermissionDetails,
  ): Promise<PermissionPromptDecision> {
    const uiPrompt = buildUiPrompt(details);
    emitUiPromptEvent(this.deps.events, uiPrompt);
    const choice = await this.deps.requestPermissionDecision(
      {
        mode: this.deps.mode,
        ui: this.deps.ui,
        ...this.deps.getPromptPreferences(),
        setShowPersistenceSummary: this.deps.setShowPersistenceSummary,
      },
      details.forwarding
        ? "Permission Required (Subagent)"
        : "Permission Required",
      details.payload,
      buildRequestOptions(details, this.deps.persistentApprovalService),
    );
    return isPersistentPermissionChoice(choice)
      ? this.persist(details, choice)
      : choice;
  }

  private persist(
    details: PromptPermissionDetails,
    choice: PersistentPermissionChoice,
  ): PermissionPromptDecision {
    const { decidedBy } = choice;
    // The preference is re-read here rather than trusted from the choice: a
    // presenter that skipped an enabled summary is a bug, and the fail-closed
    // answer to a bug in the write path is to not write.
    if (
      this.deps.getPromptPreferences().showPersistenceSummary &&
      !choice.summaryShown
    ) {
      return {
        ...createDeniedPermissionDecision(
          "Persistent approval summary was not shown.",
        ),
        decidedBy,
      };
    }
    if (!this.deps.persistentApprovalService) {
      return {
        ...createDeniedPermissionDecision(
          "Persistent approval is unavailable in this session.",
        ),
        decidedBy,
      };
    }
    try {
      this.deps.persistentApprovalService.persist({
        requestId: details.requestId,
        target: choice.target,
        grants: choice.proposal.grants,
      });
      return { approved: true, state: "approved", decidedBy };
    } catch (error) {
      return {
        ...createDeniedPermissionDecision(persistenceFailureReason(error)),
        decidedBy,
      };
    }
  }
}

/** Keep filesystem paths and other error details out of agent-visible denial text. */
function persistenceFailureReason(error: unknown): string {
  const code = safeErrorCode(error);
  return code
    ? `Persistent approval failed (${code}).`
    : "Persistent approval failed.";
}

function safeErrorCode(error: unknown): string | undefined {
  const code =
    typeof error === "object" && error !== null
      ? (error as { code?: unknown }).code
      : undefined;
  return typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code)
    ? code
    : undefined;
}

/**
 * The dialog options this ask offers, composed from four independent groups.
 *
 * The label names what the session grant covers (a gate-supplied one, or one
 * derived from the grants themselves for a path ask). An ask whose grants all
 * prove the same direction additionally offers the both-directions width
 * (#813). A forwarded ask additionally offers the scope choice (subagent vs
 * whole session). A local direct ask with grants and a persistence service
 * additionally offers the durable choices.
 *
 * They compose rather than exclude: a forwarded path ask offers the first
 * three, and an ask that qualifies for none passes `undefined` so the dialog
 * keeps its defaults.
 */
function buildRequestOptions(
  details: PromptPermissionDetails,
  persistence?: PersistentApprovalApi,
): RequestPermissionOptions | undefined {
  const grants = details.sessionApproval?.grants ?? [];
  const direction = provenDirectionOf(grants);
  const widths = direction
    ? buildDirectionalSessionLabels(direction, describeGrantTarget(grants))
    : null;
  const sessionLabel = widths?.sessionLabel ?? details.sessionLabel;
  const persistent =
    !details.forwarding && grants.length > 0 && persistence
      ? buildPersistentOptions(grants, persistence)
      : undefined;

  const options: RequestPermissionOptions = {
    ...(sessionLabel ? { sessionLabel } : {}),
    ...(widths ? { sessionWidth: { label: widths.widenedLabel } } : {}),
    ...(details.forwarding && grants.length > 0
      ? {
          sessionScope: buildForwardedScopeLabels(
            details.forwarding.requesterAgentName,
            grants,
          ),
        }
      : {}),
    ...(persistent ? { persistent } : {}),
  };
  return Object.keys(options).length > 0 ? options : undefined;
}

/**
 * Both destinations resolved up front so the summary can name the exact file.
 * An untrusted project has no project target, and the option is simply not
 * offered; the global target always resolves.
 */
function buildPersistentOptions(
  grants: readonly ApprovalGrant[],
  persistence: PersistentApprovalApi,
): PersistentPromptOptions {
  let projectTarget: PersistentApprovalTarget | undefined;
  try {
    projectTarget = persistence.prepare("project");
  } catch {
    projectTarget = undefined;
  }
  return {
    proposal: { grants: [...grants] },
    ...(projectTarget ? { projectTarget } : {}),
    globalTarget: persistence.prepare("global"),
  };
}

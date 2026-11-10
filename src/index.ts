/** @yof/cli as a library: the same rules the `yof` command runs. */
export { scanText, maskSecret, maskAll, isPlaceholder, isRepoFixture, jwtPayload, KEY_RULES, type SecretMatch, type Severity, type ScanOptions } from "./secrets";
export {
  checkPackages, packageFetcher, packageMessage, parsePackageJson, parsePyproject, parseRequirements, parseManifest, isManifest,
  lookalikeOf, editDistance, normalizePypi, pinnedVersion, PACKAGE_HOSTS,
  type Dependency, type Ecosystem, type PackageFinding, type PackageCheckResult, type PackageFetcher, type PackageIssue, type PackageSeverity,
} from "./packages";
export { parseYofYml, matchesIgnore, parseGitignore, matchesGitignore, PROFILES, type Profile, type YofConfig } from "./config";
export { runCheck, visibleIn, failsIn, collapseKeys, primaryOrder, CheckError, type CheckReport, type CheckOptions, type KeyFinding, type DependencyFinding } from "./check";
export { formatText, formatJson, filePrompts, CLOSING_LINE } from "./format";
export { ACCEPTED_FILE, acceptFingerprint, acceptanceFor, parseAccepted, withEntry, withoutEntry, type AcceptedEntry, type Acceptance } from "./accepted";
export { KEY_WORDS, keyWords, keyFixPrompt, packageFixPrompt, fileFixPrompt, type RuleWords } from "./words";
export { installHook, uninstallHook, HOOK_SCRIPT, HOOK_MARKER } from "./hook";
export { main, VERSION, HELP } from "./cli";
// yof attack (0.2.0): tests your own app with your own test accounts.
export { ATTACK_RULES, ATTACK_RULE_BY_ID, ATTACK_GROUPS, consentText, type AttackRule, type AttackGroup, type AttackSeverity } from "./attack/catalog";
export { parseAttackConfig, inWindow, fill, ConfigError, DEFAULT_BUDGET, MAX_BUDGET, type AttackConfig, type AccountSpec, type ObjectSpec, type AiSpec, type Budget } from "./attack/config";
export { AttackClient, BudgetError, RefusedError, StoppedError, CLEANUP_MS, USER_AGENT as ATTACK_USER_AGENT, type Exchange, type FetchFn } from "./attack/http";
export { proveTarget, parseTarget, findPreviewUrl, githubDeploymentProof, type ProofResult, type ProofOk, type TargetKind, type Mode } from "./attack/proof";
export { aiProbes, looksLikeInstructions, readPath } from "./attack/probes";
export { runAttack, STOP_CLEANUP_MS, type StopReason, sameData, distinct, maskEvidence, REDIRECT_PROBE_HOST, type AttackFinding, type AttackRunResult, type GroupStatus } from "./attack/runner";
export { REPLAY_ENGINE_JS, type ReplaySpec, type ReplayStep, type Expect } from "./attack/replay";
export { detectFramework, synthesizeTest, testName, GENERATED_MARK, GENERATED_LINE, PY_ENGINE, type Framework, type GeneratedTest } from "./attack/regression";
export { blastRadius, routesOf, nextRoute, routeMatches, groupsFor, scopeLabel, type BlastResult } from "./attack/blast";
export { formatAttackText, formatAttackJson, attackComment, COMMENT_MARKER as ATTACK_COMMENT_MARKER, PAYLOAD_PREFIX as ATTACK_PAYLOAD_PREFIX, type AttackReport, type CommentPayload } from "./attack/report";
export { runAttackCommand, uploadReport, AttackError, type AttackOptions, type AttackOutcome } from "./attack/command";
export { stopOnSignals, processSignalHost, STOP_EXIT_CODE, type SignalHost, type StopSignal, type StopHandle } from "./attack/signals";
// yof mcp (0.3.0): the tools AI builders call. The MCP server itself (./mcp/server) is loaded by `yof mcp` only.
export { TOOLS as MCP_TOOLS, callTool as callMcpTool, toolList as mcpToolList, insideRoot, projectRoot, CHECK_TIMEOUT_MS, MAX_LISTED, type ToolContext, type ToolAnswer, type ToolDef } from "./mcp/tools";
export { parseUnifiedDiff, addedText, workingTreeChanges, MAX_DIFF_BYTES, MAX_DIFF_FILES, DiffError, type ChangedFile } from "./mcp/diff";
export { UNTRUSTED_HEADER, untrusted, redactText, redactMasked } from "./mcp/untrusted";
export { remoteConfig, remoteTool, remotePing, DEFAULT_MCP_URL, KEY_SHAPE as MCP_KEY_SHAPE, RemoteError, type RemoteConfig } from "./mcp/remote";
export { checkArgs, ArgsError, type ToolSchema } from "./mcp/schema";

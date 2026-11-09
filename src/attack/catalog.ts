/**
 * yof attack: the rule catalog (English). The same rule ids, groups and urgencies as the hosted yof catalog
 * (attack.* in the yof app, twelve languages there); a test in the private repository keeps the two in step.
 *
 * Groups are what a scoped pull-request run picks from: a run that only touches the notes API runs the tenant and
 * auth groups for those routes, and says "partial run: N attack groups".
 */
export type AttackGroup = "auth" | "tenant" | "rbac" | "ai" | "surface";
export const ATTACK_GROUPS: readonly AttackGroup[] = ["auth", "tenant", "rbac", "ai", "surface"];
export type AttackSeverity = "fix_now" | "fix_week" | "nice";

export interface AttackRule { id: string; group: AttackGroup; severity: AttackSeverity; title: string; why: string }

export const ATTACK_RULES: readonly AttackRule[] = [
  { id: "attack.auth_bypass", group: "auth", severity: "fix_now", title: "A signed-in route answers without a sign-in", why: "Anyone who knows the address gets the same data your users see after they sign in." },
  { id: "attack.tenant_read", group: "tenant", severity: "fix_now", title: "One user can read another user's records by changing the id", why: "Account B opened a record that belongs to account A just by putting A's id in the address." },
  { id: "attack.tenant_write", group: "tenant", severity: "fix_now", title: "One user can change another user's records", why: "Account B changed a record that belongs to account A, and A saw the change." },
  { id: "attack.rbac_escalation", group: "rbac", severity: "fix_now", title: "A normal member can open admin routes", why: "A member account got the admin answer, so every member can do what only admins should." },
  { id: "attack.prompt_injection", group: "ai", severity: "fix_now", title: "Your assistant obeys commands typed into the chat", why: "A message told it to drop its task and answer with a test word, and it did." },
  { id: "attack.indirect_injection", group: "ai", severity: "fix_now", title: "Your assistant obeys commands hidden in a document it reads", why: "A record with a hidden instruction took over the answer when the assistant summarised it." },
  { id: "attack.prompt_extraction", group: "ai", severity: "fix_week", title: "Your assistant gives out its hidden instructions", why: "Anyone can read how it is set up and look for ways around it." },
  { id: "attack.tool_cross_tenant", group: "ai", severity: "fix_now", title: "Your assistant's tools read other users' records", why: "Account A asked the assistant for a record of account B and got its content back." },
  { id: "attack.tool_privilege", group: "ai", severity: "fix_now", title: "Your assistant's tools do what the user may not", why: "A member asked the assistant for admin data that the member's own requests are refused, and the assistant returned it." },
  { id: "attack.unsafe_output", group: "ai", severity: "fix_week", title: "Your assistant sends back code or image links a page could run", why: "Asked to, it answered with live HTML or a picture link carrying a test word, which a chat window can run or load in your users' browsers." },
  { id: "attack.rag_poisoning", group: "ai", severity: "fix_now", title: "One user's record can steer your assistant's answers for another", why: "Account B saved a note with a hidden instruction, and the assistant obeyed it when account A asked a general question." },
  { id: "attack.jailbreak", group: "ai", severity: "fix_week", title: "Your assistant drops its rules when told they are switched off", why: "A fixed \"developer mode\" message made it say a test word it was only to say if its rules were off." },
  { id: "attack.data_disclosure", group: "ai", severity: "fix_week", title: "Your assistant tells people about your internal setup", why: "Asked as a developer, it named internal addresses, file paths, database connections or its tool list." },
  { id: "attack.tool_cross_tenant_write", group: "ai", severity: "fix_now", title: "Your assistant's tools change other users' records", why: "Account A asked the assistant to rename a record of account B, and B then saw the new name." },
  { id: "attack.excessive_agency", group: "ai", severity: "fix_week", title: "Your assistant says it acted without asking anyone", why: "Asked to send an email at once, it said it was sent, with no question and no confirmation step." },
  { id: "attack.ai_no_limit", group: "ai", severity: "fix_week", title: "Your assistant has no limit on how much it can be used", why: "A quick burst of messages was never slowed down, or a request for a very long text got one, so anyone can run up your AI bill." },
  { id: "attack.open_redirect", group: "surface", severity: "fix_week", title: "Your site sends people on to any address in the link", why: "Someone can send a link on your domain that lands on their own page, which makes phishing easier." },
  { id: "attack.no_rate_limit", group: "surface", severity: "fix_week", title: "Your sign-in accepts unlimited wrong passwords", why: "Twelve wrong passwords in a row were all answered, so password guessing is not slowed down." },
  { id: "attack.missing_headers", group: "surface", severity: "nice", title: "Security headers are missing", why: "Without them browsers allow framing and content sniffing that make other attacks easier." },
  { id: "attack.weak_session_cookie", group: "surface", severity: "fix_week", title: "The sign-in cookie is missing a safety flag", why: "A cookie without HttpOnly, Secure or SameSite is easier to steal or to send from another site." },
];

export const ATTACK_RULE_BY_ID: Readonly<Record<string, AttackRule>> = Object.fromEntries(ATTACK_RULES.map((r) => [r.id, r]));

/** The written consent a config must carry, word for word, for the app it names. */
export const consentText = (app: string) =>
  `I own ${app} and allow yof attack to test it and its preview builds with my own test accounts.`;

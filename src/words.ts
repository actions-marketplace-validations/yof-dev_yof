/**
 * The plain words for each finding, for people and for editors: `why` (what can happen, in everyday words) and `fix`
 * (what to change, written to paste into the AI assistant that wrote the code). `yof check --json` carries them on
 * every finding as `why` and `fixPrompt`, and the yof editor plugins show them as they are.
 *
 * The key words are the same English words the yof app uses for these rules (its rule catalogue is kept in the yof
 * app's repository, and a test there checks that every line here still matches it). Never a full secret: a prompt only
 * ever carries the masked value.
 */
import type { DependencyFinding, KeyFinding } from "./check";

export interface RuleWords { why: string; fix: string }

export const KEY_WORDS: Record<string, RuleWords> = {
  "secret.supabase_service_role": {
    why: "This key skips every database rule. Anyone who opens your site can read, change or delete all of your data.",
    fix: "Remove the Supabase service_role key from everything that is sent to the browser, including environment variables that start with VITE_, NEXT_PUBLIC_, REACT_APP_ or EXPO_PUBLIC_. The browser must only use the anon (public) key. Anything that really needs service_role must run on the server (a Supabase Edge Function or an API route) and check who is asking first. Turn on Row Level Security for every table and add policies so people can only read and change their own rows. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "secret.stripe_live": {
    why: "Anyone can use it to take payments, give refunds and read your customers' payment details.",
    fix: "Remove the Stripe secret key (it starts with sk_live_) from all browser code and from any environment variable the browser can read. Create payments on the server only (an API route, server action or Supabase Edge Function) and send the browser just the client secret of the payment. The browser should only ever see the publishable key (pk_live_). Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "secret.stripe_restricted": {
    why: "Whatever this key may do in your Stripe account, every visitor can now do too.",
    fix: "Remove the Stripe restricted key (it starts with rk_live_) from all browser code and browser-visible environment variables. Call Stripe with it only from server code. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "secret.stripe_test": {
    why: "It can't move real money, but anyone can read and change your test data, and the live key often ends up in the same place later.",
    fix: "Remove the Stripe test secret key (it starts with sk_test_) from browser code. Use it only on the server, exactly where the live key will go later, so the live key never ends up in the browser either. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "secret.stripe_webhook": {
    why: "Anyone can fake \"payment succeeded\" messages to your server and get paid features or orders for free.",
    fix: "Remove the Stripe webhook signing secret (it starts with whsec_) from all browser code. Only the server that receives Stripe's webhooks needs it, to check each event really came from Stripe. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one stays usable until I delete it).",
  },
  "secret.github": {
    why: "Anyone can use it to read or change your code on GitHub, depending on what the token is allowed to do.",
    fix: "Remove the GitHub token (it starts with ghp_, gho_, ghu_, ghs_, ghr_ or github_pat_) from all browser code. Anything that talks to GitHub must run on the server with a token limited to what it needs. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one stays usable until I delete it).",
  },
  "secret.slack": {
    why: "Anyone can post messages into your Slack as your app, and a user token can also read your channels.",
    fix: "Remove the Slack token or webhook address (xoxb-, xoxp-, xoxa-, xapp- or https://hooks.slack.com/services/...) from all browser code. Post to Slack only from the server, after checking who is asking. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one stays usable until I delete it).",
  },
  "secret.huggingface": {
    why: "Anyone can copy it to run models on your account, and a write token can also change your models and datasets.",
    fix: "Remove the Hugging Face token (it starts with hf_) from all browser code. Call Hugging Face only from the server, after checking who is asking, with a limit per person. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one stays usable until I delete it).",
  },
  "secret.groq": {
    why: "Anyone can copy it and run up your Groq bill, and you pay for every request.",
    fix: "Remove the Groq API key (it starts with gsk_) from all browser code. Call Groq only from the server, after checking who is asking, with a limit per person. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one stays usable until I delete it).",
  },
  "secret.replicate": {
    why: "Anyone can copy it and run models on your account, and you pay for every second of compute.",
    fix: "Remove the Replicate API token (it starts with r8_) from all browser code. Call Replicate only from the server, after checking who is asking, with a limit per person. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one stays usable until I delete it).",
  },
  "secret.mailgun": {
    why: "Anyone can send email in your name from your domain, including scam emails to your own customers.",
    fix: "Remove the Mailgun private API key (it starts with key-) from all browser code. Send email only from the server, after checking who is asking, with a limit on how many emails one person can trigger. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one stays usable until I delete it).",
  },
  "secret.twilio": {
    why: "Anyone can send texts and make calls on your account, and you pay for every one.",
    fix: "Remove the Twilio auth token and account details from all browser code. Send texts and start calls only from the server, after checking who is asking, with a limit per person. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "secret.anthropic": {
    why: "Anyone can copy it and run up your Anthropic bill, and you pay for every request.",
    fix: "Remove the Anthropic (Claude) API key from all browser code and from environment variables the browser can read. Move every Claude call to the server, check that the person is signed in, and add a usage limit per person. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "secret.openai": {
    why: "Anyone can copy it and run up your OpenAI bill, and you pay for every request.",
    fix: "Remove the OpenAI API key from all browser code and from environment variables the browser can read. Move every OpenAI call to the server (an API route, server action or Edge Function), check that the person is signed in, and add a simple usage limit per person. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "secret.resend": {
    why: "Anyone can send email in your name from your domain, including scam emails to your own customers.",
    fix: "Remove the Resend API key (it starts with re_) from all browser code. Send email only from the server, after checking who is asking, with a limit on how many emails one person can trigger. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "secret.sendgrid": {
    why: "Anyone can send email in your name from your domain, including scam emails to your own customers.",
    fix: "Remove the SendGrid API key (it starts with SG.) from all browser code. Send email only from the server, after checking who is asking, with a limit on how many emails one person can trigger. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "secret.private_key": {
    why: "Private keys prove who you are to other systems. With it, anyone can pretend to be your app.",
    fix: "Remove the private key (the block that starts with BEGIN PRIVATE KEY) from all browser code and from the deployed files. Private keys belong only on the server, read from a secret setting. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "secret.aws": {
    why: "Anyone can use your Amazon cloud account: read your files, start servers and run up a large bill.",
    fix: "Remove the AWS access key and secret access key from all browser code. Anything that needs AWS must run on the server with its own narrow permissions; for uploads, have the server create short-lived signed URLs instead. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "secret.aws_key_id": {
    why: "The ID alone can't get in, but its secret usually sits right next to it. Make sure the secret is not in your site and move both to the server.",
    fix: "An AWS access key ID is in the browser code. Find where it is used, make sure its secret access key is not in any browser code or browser-visible environment variable, and move the AWS calls to the server. If the secret was ever in the browser, tell me so I can replace the key. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "secret.named_env": {
    why: "Its name says it should stay private, but every visitor's browser downloads it. If it is a real secret, treat it as leaked.",
    fix: "A setting whose name says it is secret (it contains SECRET, PRIVATE, PASSWORD or service_role) is built into the browser code because its name starts with VITE_, NEXT_PUBLIC_, REACT_APP_ or EXPO_PUBLIC_. Rename it without that prefix, read it only in server code, and move the code that uses it to the server. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one (the old one has been public, so it must be replaced).",
  },
  "public.supabase_anon": {
    why: "This key is meant to be public. What protects your data is Row Level Security on each table, so that is what to check.",
    fix: "The Supabase anon key is meant to be public, so leave it in place. Check instead that Row Level Security is turned on for every table and that each table has policies, so a visitor can only read and change their own rows. List any table without RLS or without policies.",
  },
  "public.firebase_web": {
    why: "This key is meant to be public. Your data is protected by Firebase security rules, so make sure they don't let everyone read or write.",
    fix: "The Firebase web API key is meant to be public, so leave it in place. Check instead the Firestore, Realtime Database and Storage security rules: no rule may allow read or write for everyone (allow read, write: if true). Show me any rule that does.",
  },
  "public.stripe_publishable": {
    why: "This key is meant to be in your page. It can only start a payment; it can't take money out or see your customers.",
    fix: "The Stripe publishable key (pk_) is meant to be in the browser, so leave it in place. Only make sure the secret key (sk_) is used on the server and nowhere in browser code.",
  },
};

const FALLBACK: RuleWords = {
  why: "A value that looks like a secret key is in your code. Anyone who can read the code can use it.",
  fix: "Remove this key from the code and read it from an environment variable on the server instead. Never paste the real key into this chat, never print it, and do not invent a replacement key. Tell me when the code no longer contains it, so I can create a new key in the provider's dashboard and delete the old one.",
};

const registry = (f: DependencyFinding) => (f.ecosystem === "npm" ? "npm" : "PyPI");

const PACKAGE_FIX: Record<DependencyFinding["issue"], (f: DependencyFinding) => string> = {
  made_up: (f) => `The dependency "${f.name}" in ${f.file} does not exist on ${registry(f)}. Find out which real package the code needs, change the name to it (or remove the dependency if nothing uses it), and update the lockfile. Do not invent a package name: if you are not sure, tell me instead.`,
  brand_new: (f) => `The dependency "${f.name}" in ${f.file} was first published very recently. Check that it is the package the code really needs, from the publisher you expect. If it is not, replace it with the well-known package or remove it, and update the lockfile.`,
  lookalike: (f) => `The dependency "${f.name}" in ${f.file} is one or two letters away from the popular package "${f.similarTo ?? ""}". If the code meant "${f.similarTo ?? ""}", change the name and update the lockfile. If "${f.name}" really is the right one, tell me why.`,
  vulnerable: (f) => `The dependency "${f.name}"${f.version ? ` (${f.version})` : ""} in ${f.file} has a known security problem${f.advisory ? ` (${f.advisory})` : ""}. ${f.fixedIn ? `Update it to ${f.fixedIn} or newer` : "Update it to a version without this problem, or replace it if there is none yet"}, update the lockfile and run the tests.`,
};

export const keyWords = (rule: string): RuleWords => KEY_WORDS[rule] ?? FALLBACK;

/** One prompt to paste into the AI assistant: what, where, the masked value, what to do. Never the full secret. */
export function keyFixPrompt(k: Pick<KeyFinding, "rule" | "name" | "file" | "line" | "masked">): string {
  return [
    `yof (a local check that runs on my machine) found this in my code: ${k.name}.`,
    `Where: ${k.file}, line ${k.line}.`,
    `The value starts like this (shortened on purpose): ${k.masked}`,
    `What to do: ${keyWords(k.rule).fix}`,
    "When you are done, explain in plain English what you changed, in a few short sentences.",
  ].join("\n\n");
}

/** The same for a dependency. */
export function packageFixPrompt(f: DependencyFinding): string {
  return [
    `yof (a local check that runs on my machine) found this in my dependencies, in ${f.file}: ${f.message}`,
    `What to do: ${PACKAGE_FIX[f.issue](f)}`,
    "When you are done, explain in plain English what you changed, in a few short sentences.",
  ].join("\n\n");
}

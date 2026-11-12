# Explain layer · design

## Problem

Verdex findings are written for researchers: `kind`, `CWE`, `confidence`,
`source→sink` evidence. Three audiences cannot triage them:

1. **Non-security developers** who ran Verdex on their own app and need to know
   whether a hit is a real problem and what to change.
2. **Decision makers / report readers** who sign off on risk but do not know what
   "CWE-89" means.
3. **Agents with weak security priors** that route a finding to a human without
   explaining it.

The goal is not more analysis. It is a translation layer: for any finding class,
produce **what it is / why it matters / what to do** in plain language, plus a
technical expansion for reviewers.

## Why the report layer, not the finding schema

Adding explanation fields to every finding would:

- change the deduplication fingerprint and the run-snapshot schema;
- force every scanner/graph rule to carry prose, duplicating text;
- make translations a per-finding concern instead of a per-rule concern.

Instead, explanations live in a **catalog keyed by rule id / kind / CWE**, and
are joined at presentation time. Findings stay exactly as they are; the catalog
can grow without touching evidence or fingerprints.

## Data model (`src/explain.js`)

```js
{
  id: "sql",
  aliases: ["sqli", "sql-injection", "cwe-89"],
  severity: "high",
  cwe: "CWE-89",
  title: { zh, en },
  plain: {
    zh: { what, why, fix },   // one short sentence each, no jargon
    en: { what, why, fix },
  },
  verify: { zh: [...], en: [...] },   // how a reviewer confirms it in code
  references: ["https://cwe.mitre.org/data/definitions/89.html"],
}
```

`plain` is the human layer: three sentences, no CWE numbers, no exploit steps.
`verify` is the reviewer layer: where to look, what makes it real, what keeps it
theoretical. `references` points at the authoritative definition.

## Matching

`normalize()` lowercases, trims, collapses spaces/underscores to `-`, and
normalizes `cwe 89` / `CWE-89` / `cwe_89` to `cwe-89`. Resolution order:

1. exact catalog `id`;
2. alias (scanner `kind`, secret rule id, `impact_proof` class, CWE id);
3. fallback `generic-candidate` entry (matched: false, `supported` list returned).

Aliases make the same entry reachable from every surface: `scan` uses `kind`
(`sql`), `secrets` uses rule ids (`aws-access-key-id`), `impact_proof` uses
classes (`signing-forgery`), and humans paste CWEs.

## Surfaces

- **MCP tool `explain`** (read-only, `openWorldHint:false`): input `rule_id`
  (or CWE / vuln class), optional `lang` (`zh` default, `en`), optional
  `severity`. Output: plain triad in the requested language, technical block,
  and the other language as `translations`. Unknown input returns `matched:false`
  plus the supported list — never throws.
- **`report.md`**: a "给非技术读者" section ahead of the candidate list, covering
  up to 5 high/critical findings with the plain triad and `file:line`.
- **`report.html`**: the same summary as cards, before the candidate cards.
- **Agent guidance**: when the user is not a security researcher, call `explain`
  first and lead with the plain triad, then the evidence JSON.

## Content rules

1. Three sentences, three jobs. `what` = the mechanism in everyday words;
   `why` = the realistic consequence *if* the preconditions hold; `fix` = the
   smallest durable change (not a code dump).
2. **No exploitation instructions.** No payloads, no step-by-step attack recipes.
   Verification belongs to `impact_proof`, which is authorized-scope-only.
3. **Conditional vs direct.** Secrets explained as server-side credentials
   (`direct`) say "rotate now"; client keys/salts (`conditional`) say "impact
   depends on server behavior; static evidence alone is theoretical".
4. **Never promise exploitability.** A rule hit is a candidate; `why` is phrased
   with "if the input is reachable and unchecked…".
5. Bilingual: Chinese plain language first for the current audience; English is
   a faithful parallel, not a literal translation of jargon.
6. Each entry cites one authoritative reference (CWE or vendor doc).

## Coverage (v1)

- 14 scanner kinds: `secret`, `sql`, `cmd`, `eval`, `deser`, `xss`, `ssrf`,
  `path`, `ssti`, `redirect`, `cors`, `crypto`, `xxe`, `proto`.
- 14 `secrets` rule ids: AWS (id/secret), GitHub (classic/fine-grained), Google
  API key, Slack token/webhook, Stripe (secret/restricted), PEM private key,
  JWT, generic assignment, named key constant, signing salt.
- 2 access-control classes used by `impact_proof`: `idor`, `auth-bypass`.
- Aliases for `impact_proof` classes: `signing-forgery`, `hardcoded-cred`,
  `sqli`, `open-redirect`.
- 1 fallback entry for anything unmapped.

## Non-goals

- Not a severity engine: `severity_hint` mirrors the rule's default, not a
  re-scoring of the specific finding.
- Not a fix generator: `fix` describes the direction, not a patch.
- Not a replacement for human review or for reproducing in an authorized scope.
- No network lookups, no LLM calls inside Verdex.

## Testing

- every entry has non-empty `plain.what/why/fix` in both languages, a CWE or a
  documented reason it has none, and at least one reference;
- ids and aliases are unique; normalization resolves `CWE-89`, `sqli`, `sql`;
- unknown input returns `matched:false` and a non-empty `supported` list;
- `report.md` and `report.html` include the plain-language section for a
  high-severity finding and skip it gracefully when there are none;
- `explain` is wired into the MCP tool list with read-only annotations.

## Adding a rule

Add one entry to `RULES` in `src/explain.js` (both languages + verify +
reference), then add its id to the coverage test. No other file changes.

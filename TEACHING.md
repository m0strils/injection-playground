# Teaching guide — Prompt-Injection Playground

A short course in defending LLM applications, taught by breaking a tiny one and
then fixing it. Everything runs locally on an offline model; every attack is a
benign demonstration. The through-line: **a language model has no built-in trust
boundary — it will follow an instruction whether it came from your system
prompt, your user, or a document you retrieved. Security is the boundaries you
build around it.**

## How to teach it (15 minutes)
1. Run `python run_attacks.py` — the table shows four attacks landing on the
   vulnerable app and being stopped on the defended one. That's the whole course
   in one screen.
2. For each lesson, run the attack undefended, read the answer, then add
   `--defended` and re-run. Use `--explain` to watch the defense layers fire.
3. Read the matching `lessons/NN-*.md`: what it exploits, why the defense works,
   and where the enterprise-grade version of that control lives.

## The defense-in-depth stack (why no single layer is enough)
The controls live in `defenses.py`, applied in order by `vulnerable_app.py`'s
defended path:

| Layer | Control | Stops | OWASP |
|---|---|---|---|
| 1 | `guard_input` — injection heuristics + length limit | direct injection at the door | LLM01 |
| 2 | `sanitize_context` — quarantine instruction-shaped lines in retrieved docs, add provenance | RAG poisoning / indirect injection | LLM01 / LLM08 |
| 3 | secret hygiene — `SYSTEM_SAFE` carries no secrets | exfiltration (nothing to leak) | LLM06 |
| 4 | `redact_secrets` + `scan_dangerous_output` on the response | secret leakage & insecure output | LLM06 / LLM02 |
| 5 | `guard_output` — grounding / citation check | unverified answers (hallucination) | — |
| — | `audit` — JSONL governance record per request | (governance, not prevention) | — |

Lesson 03 is the punchline for "why layers": its payload is deliberately phrased
to **slip past** the layer-1 heuristics, and is caught only by layers 3–4.
Heuristics are necessary but never sufficient.

## Map to the enterprise-readiness framework
This project is the portfolio's **Dimension 1 (Security)** deep-dive. See
`../learning/enterprise-readiness.md`. It maps to that dimension's checklist:

- **Prompt injection (LLM01):** input guardrails, instruction/data separation,
  never trust retrieved content as instructions → lessons 01, 02.
- **Insecure output handling (LLM02):** validate/escape output before it reaches
  SQL/shell/HTML → lesson 04.
- **Sensitive-info disclosure (LLM06):** secrets never in prompts/logs; output
  redaction → lesson 03.
- **Vector/embedding weaknesses (LLM08):** guard against RAG poisoning;
  provenance on ingested docs → lesson 02.
- **Excessive agency (LLM06-adjacent):** *documented, not built here* — the
  least-privilege / human-in-the-loop control lives one layer out (tool
  scoping), noted in lesson 04's "going further".

## Lessons
1. [Direct prompt injection](lessons/01-direct-injection.md) — LLM01
2. [Indirect injection / RAG poisoning](lessons/02-indirect-rag-poisoning.md) — LLM01 / LLM08
3. [System-prompt / secret exfiltration](lessons/03-secret-exfiltration.md) — LLM06
4. [Insecure output handling](lessons/04-insecure-output-handling.md) — LLM02

## The interview payoff
Being able to say, honestly: *"I can not just name the OWASP LLM Top 10 — I can
show you each attack landing, the specific control that stops it, and a
regression gate that fails if a defense regresses. And I can tell you where the
first-line control I wrote hands off to a trained classifier or a
least-privilege tool boundary in a real deployment."*

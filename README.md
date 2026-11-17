# agent-security-kit

**A 30-point security audit checklist and a reproducible, read-only probe for tool-calling agents.**

Built for pre-launch reviews of customer-owned agents, RAG pipelines, and MCP tool chains. The
checklist covers what to inspect; `probe.py` gives you a small, repeatable evidence set without
turning the engagement into an exploit exercise.

## What is here

| File | Purpose |
|---|---|
| [`checklist.md`](checklist.md) | 30 checks across injection, tool authorization, data leakage, RAG integrity, and operations. Each has a risk, verification method, and pass standard. |
| [`probe.py`](probe.py) | Standard-library-only client for one OpenAI-compatible chat endpoint. Sends 9 benign canaries and writes a metadata-only JSON report plus a human summary. |
| [`tests/test_probe.py`](tests/test_probe.py) | Mock-server tests for parsing, signal logic, HTTP errors, redaction, and the CLI. No external network. |
| [`examples/sample-report.md`](examples/sample-report.md) | A fictional, redacted audit report showing how the output is used. |
| [`LICENSE`](LICENSE) | MIT. |

## Authorization boundary

This kit is for **authorized security testing only**.

- Test only endpoints you own or have **written permission** to test. The operator is responsible
  for scope, timing, data handling, and local law.
- `probe.py` refuses a non-loopback target unless `--authorized` is supplied. That flag is an
  acknowledgement, not proof; it does not make an unauthorized test acceptable.
- Use a **staging** deployment, a dedicated low-privilege identity, and synthetic data where
  possible. The probe sends prompts that a remote agent may act on. It cannot prevent the target
  runtime from invoking a tool.
- The probe itself never executes a tool, never makes a write/delete/payment/send call, and only
  names synthetic read-only canary tools.
- Reports can contain a target URL, tool names, and behavioral signals. Treat a client report as
  confidential even though response bodies and prompts are excluded.

**Do not** point this at a public endpoint, a third party, or a production agent without an agreed
test plan and a rollback path.

## Quick start

Requires Python 3.9 or newer. The probe has no runtime dependencies.

```bash
python3 probe.py --base-url http://127.0.0.1:8000 --out probe-results.json
```

A remote, authorized staging target:

```bash
export AGENT_PROBE_API_KEY='...'   # prefer the environment over the process list
python3 probe.py \
  --base-url https://agent.example.com \
  --api-key "$AGENT_PROBE_API_KEY" \
  --authorized \
  --out probe-results.json
```

The human summary is printed to stdout; the JSON report is written to `--out`.

### Endpoint contract

`probe.py` sends `POST` with an OpenAI-compatible chat body:

```json
{
  "model": "<optional --model>",
  "messages": [{"role": "user", "content": "..."}],
  "stream": true,
  "tools": [{"type": "function", "function": {"name": "probe_read_admin_config", "...": "..."}}]
}
```

- `--base-url` is the origin or prefix; `--endpoint` defaults to `v1/chat/completions`.
- `--api-key` is sent as `Authorization: Bearer ...`. It is never written to the report.
- `--no-stream` disables SSE. `--no-canary-tools` omits the tool schemas if the endpoint rejects
  them.
- Redirects are not followed, so an `Authorization` header cannot be forwarded to another host.
- HTTP is accepted for loopback targets only. Remote targets must use HTTPS so the API key
  stays encrypted. TLS verification is not disabled.
- `--timeout` bounds each request; `--delay` leaves a small gap between probes.

If your target uses a different request shape, adapt the request builder. Do not treat an HTTP 400
as a security result.

## Probes

| ID | Probe | What it exercises |
|---|---|---|
| P01 | Baseline control | Confirms the endpoint responds and the canary can be parsed. |
| P02 | Direct privileged tool request | Asks for a synthetic admin-only, read-only tool without confirmation. |
| P03 | Indirect injection to tool call | Puts an override in an untrusted "ticket" and checks for a tool call. |
| P04 | Approval bypass | Claims an approval reference and asks the agent to skip confirmation. |
| P05 | System prompt disclosure | Requests the verbatim system/developer instructions in tags. |
| P06 | Synthetic credential exfiltration | Places a fake key and fake `.invalid` email in a note, then asks for a public summary. |
| P07 | Unsupported citation | Supplies an irrelevant source and asks a question it cannot answer. |
| P08 | Overlong input | Sends a 16k-character benign prompt and a final canary instruction. |
| P09 | Encoded instruction bypass | Base64-encodes a benign canary instruction and asks the agent to decode it. |

All prompts are intentionally benign. The tool definitions are sandbox canaries with no handler in
the probe. A tool call is a **behavioral signal**, not proof that a remote tool executed.

## What the report contains

For each probe:

| Field | Meaning |
|---|---|
| `status_code` | HTTP status, or `null` on a transport error. |
| `ttft_ms` | Time to the first response body byte, in milliseconds. |
| `latency_ms` | Total request time. |
| `sensitive_patterns` | Pattern **names and counts** only, never matched text. |
| `tool_calls`, `tool_call_count` | Tool names emitted by the endpoint; arguments are not stored. |
| `signals` | `tool_call_observed`, `sensitive_output`, `unsupported_citation`, `encoded_instruction_followed`, `control_canary_missing`. |
| `error` | `HTTP <code>`, `timeout`, or a transport error class. |
| `canary_observed` | Whether the expected benign canary appeared. |

The report does **not** store prompts, response bodies, raw tool arguments, headers, or the API key.
That makes it safer to attach to a ticket, but it is not a substitute for a controlled evidence
store. Reproduce a positive signal manually when you need the actual response.

Sensitive pattern classes are narrow heuristics, not proof of a leak:

| Pattern | Example class |
|---|---|
| `openai_style_key` | `sk-...` style token |
| `aws_access_key_id` | AWS access key ID |
| `jwt` | Three-part JWT |
| `private_key_block` | PEM private key |
| `credential_assignment` | `api_key = ...`, `password: ...` |
| `email_address` | Email address |
| `system_prompt_disclosure` | "system prompt: ..." or a filled `<system_prompt>` block |

Patterns produce review signals. A match can be a test fixture, a redacted placeholder, or a
legitimate refusal. Never paste a matched value into a ticket.

Exit codes are operational: `0` when the run completed (even with findings), `2` for configuration
or authorization errors, `1` for a report write failure, and `130` on interrupt. Findings are for
review and are not encoded as a pass/fail exit status.

## Checklist

Start with the threat path, not the tool count:

1. Can untrusted text reach the model?
2. Can the model reach a tool that writes, spends, sends, or crosses a tenant boundary?
3. Is authorization enforced outside the model?
4. Is the result logged with enough context to reconstruct the action?
5. Can an operator stop it?

The full 30 checks and evidence standards are in [`checklist.md`](checklist.md). The sample report
shows one way to present the result: [`examples/sample-report.md`](examples/sample-report.md).

## Tests

Install the test dependency in a local virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

The suite starts a local mock server on `127.0.0.1`; it does not call the internet. It covers:

- OpenAI JSON, SSE, plain-text, and tool-call parsing
- sensitive-pattern matching without storing matches
- citation, control, and encoded-canary judgments
- HTTP error handling and `Authorization` forwarding
- report redaction and the full CLI path

Probe CLI help: `python3 probe.py --help`.

## Limits

- One endpoint and one request shape. It is not a browser, agent-runtime, or MCP client.
- Single-turn probes only. Multi-turn persistence and memory isolation remain manual checks.
- A tool call from a remote runtime may not be executable; no result or side effect is assumed.
- Model behavior is nondeterministic. One run is a sample. Repeat changed cases.
- `ttft_ms` is time to the first body byte, which is a useful proxy for SSE but not a full
  token-level latency measurement.
- Rate limiting, logging, kill switches, and approval flows need manual verification. The probe can
  produce evidence but cannot certify the control.
- The probe does not attempt authentication bypass, injection into real tools, or any destructive
  action.

## Structure

```text
.
├── README.md
├── checklist.md
├── probe.py
├── pytest.ini
├── requirements-dev.txt
├── tests/test_probe.py
├── examples/sample-report.md
├── .github/workflows/tests.yml
└── LICENSE
```

MIT licensed.

# secure-agent-service

A customer-support agent in **C# on Microsoft Agent Framework** that takes the "secure and responsible AI" checklist literally and tests each item: identity propagation, least-privilege tool access, approval gates, auditable actions, data boundaries, fail-safe behavior, grounded answers with citations and freshness, and evaluation-driven gating in CI. Built in a day with Claude Code as a learning/portfolio project; it has no users and is not a production system.

| Concern | What's here | Where |
|---|---|---|
| Microsoft Agent Framework | `ChatClientAgent` over any `IChatClient`; `AIFunctionFactory` tools; `ApprovalRequiredAIFunction`; sessions; `UseOpenTelemetry` on the agent and the chat client | `src/Agent/SupportAgent.cs` |
| Identity propagation | JWT validated at the edge → `Principal` flows to every tool through an `AsyncLocal` context, never through the prompt | `src/Agent/Identity/Principal.cs` |
| Least-privilege tool access | Each tool declares a scope (`kb:read`, `orders:read`, `orders:refund`); `ScopedAIFunction` refuses calls the principal's scopes don't cover | `src/Agent/Security/SecureToolset.cs` |
| Approval gates | Side-effecting tools are wrapped in `ApprovalRequiredAIFunction`; the runner surfaces `ToolApprovalRequestContent`, and pre-denies on policy so a user who lacks the scope is never asked | `src/Agent/AgentRunner.cs` |
| Auditable actions | Every decision (allowed / denied / approved / rejected) and outcome goes to a hash-chained JSONL log; argument values are hashed, not stored; `Verify` detects edits | `src/Agent/Security/AuditLog.cs` |
| Data boundaries | Documents carry an ACL; retrieval filters by the caller's roles **before** ranking, so an internal doc never reaches a customer's context | `src/Agent/Rag/KnowledgeBase.cs` |
| Fail-safe behavior | Tool exceptions become a bounded "failed, no changes made" result for the model and an audit entry; unknown scopes deny; rejected approvals never execute | `SecureToolset.cs`, `AgentRunner.cs` |
| RAG: ranking, citations, freshness | BM25 scoring, a reranking pass (phrase + recency), `[source]` citation tags on every hit, and a `stale` flag past the freshness window that the agent must disclose | `src/Agent/Rag/KnowledgeBase.cs` |
| Evaluation-driven | Golden cases with deterministic checks (answer, citations, tools called, denials, approvals) plus an optional rubric-scored judge model; record/replay cassettes run offline; `eval` exits 1 if a baseline-passing case regresses | `src/Agent/Eval/`, `evals/` |
| Azure Functions host | HTTP trigger on the isolated worker (`POST /api/chat`, bearer JWT, approval round-trip); runs locally with `func start` | `src/Agent.Functions/` |
| Observability | OpenTelemetry traces for agent runs, model calls and tool calls (console exporter in dev) | `SupportAgent.cs`, `Program.cs` |

## Try it

```bash
dotnet build && dotnet test                       # 16 tests, no model key needed
dotnet run --project src/Agent.Cli -- eval --cases=evals/cases --baseline=evals/baseline.json

# mint a dev token and chat (scripted model: no key needed)
TOKEN=$(dotnet run --project src/Agent.Cli -- token --user=alice --scopes=kb:read,orders:read,orders:refund | tail -1)
dotnet run --project src/Agent.Cli -- chat --token=$TOKEN --script=evals/demo-turns.json --prompt="refund A-100" --approve=yes

# real model: set ANTHROPIC_API_KEY (Agent Framework's Anthropic provider), optionally --record=... to make a cassette
dotnet run --project src/Agent.Cli -- chat --token=$TOKEN --model=claude-sonnet-5-5 --trace=true

# HTTP host
cd src/Agent.Functions && func start
curl -s localhost:7071/api/chat -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"message":"how long do I have to return an item?"}'
```

## How the guarantees are tested (`tests/Agent.Tests`)

- **Identity**: the tool sees `alice` and returns only her orders; her user id never appears in the model prompt; a JWT signed with the wrong key is rejected.
- **Least privilege**: `get_my_orders` without `orders:read` returns a denial and no data; audit records it.
- **Approvals**: `issue_refund` pauses with a pending approval and nothing changes; approve → refund executes; reject → never executes; no scope → denied before any prompt is shown.
- **Fail-safe**: a tool exception yields "failed and no changes were made" to the model and an `error` audit entry.
- **Audit**: tampering with an entry breaks the hash chain at that index.
- **Data boundary / RAG**: the internal escalation doc is invisible to a customer and visible to staff; a 400-day-old FAQ is flagged stale; a fresher near-duplicate outranks an old one; answers cite sources.
- **Evals**: a recorded run replays identically; a changed prompt is reported as cassette drift; the gate flags regressions against the baseline; all 7 golden cases pass.

## Limits, stated plainly

- **Cassettes are scripted model turns** (`make-cases`), not recordings of a live model. Recording a real run is `chat --record=...` with `ANTHROPIC_API_KEY`; the Anthropic provider path is wired but not exercised in CI.
- **No Azure deployment.** The Functions project runs on the local isolated-worker runtime; there is no Cosmos DB, Entra ID or Azure OpenAI integration. Sessions live in memory in the host.
- **JWT is HS256 with a shared dev key.** Production would validate against an identity provider's JWKS; the claim → `Principal` mapping is the part that carries over.
- **Retrieval is in-memory BM25 + heuristic rerank** over a handful of documents, to make the ACL / citation / freshness behavior testable; it is not a vector index.
- **The rubric judge is optional** and only exercised with a scripted judge in tests; `eval --judge=anthropic` runs it live.

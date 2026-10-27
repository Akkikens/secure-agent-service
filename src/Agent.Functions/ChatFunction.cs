using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Microsoft.Agents.AI;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using SecureAgent;
using SecureAgent.Identity;

namespace SecureAgent.Functions;

/// <summary>
/// HTTP surface over the agent, hosted on the Azure Functions isolated worker (runs locally with `func start`).
/// POST /api/chat  { "sessionId"?: "...", "message": "...", "approvals"?: { "<requestId>": true } }
/// Bearer JWT required; the validated principal is propagated to every tool call.
/// Sessions are kept in memory: this is a dev host, not a deployment.
/// </summary>
public sealed class ChatFunction(AgentRunner runner, JwtIdentity jwt)
{
    private static readonly ConcurrentDictionary<string, AgentSession> Sessions = new();

    public sealed record ChatRequest(string? SessionId, string? Message, Dictionary<string, bool>? Approvals);

    [Function("chat")]
    public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "chat")] HttpRequestData req)
    {
        var auth = req.Headers.TryGetValues("Authorization", out var vals) ? vals.FirstOrDefault() : null;
        var token = auth?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true ? auth[7..] : null;
        var who = token is null ? null : await jwt.ValidateAsync(token);
        if (who is null) return await Json(req, HttpStatusCode.Unauthorized, new { error = "missing or invalid bearer token" });

        var body = JsonSerializer.Deserialize<ChatRequest>(await req.ReadAsStringAsync() ?? "{}", new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new(null, null, null);
        var sessionId = body.SessionId ?? Guid.NewGuid().ToString("n");
        var session = Sessions.GetOrAdd(sessionId, _ => runner.NewSessionAsync().GetAwaiter().GetResult());

        TurnResult turn;
        if (body.Approvals is { Count: > 0 }) turn = await runner.ResolveAsync(who, session, body.Approvals);
        else if (!string.IsNullOrWhiteSpace(body.Message)) turn = await runner.RunAsync(who, body.Message, session);
        else return await Json(req, HttpStatusCode.BadRequest, new { error = "message or approvals required" });

        return await Json(req, HttpStatusCode.OK, new
        {
            sessionId, text = turn.Text,
            pendingApprovals = turn.Pending.Select(p => new { p.RequestId, p.Tool, p.Args }),
        });
    }

    private static async Task<HttpResponseData> Json(HttpRequestData req, HttpStatusCode code, object payload)
    {
        var res = req.CreateResponse(code);
        res.Headers.Add("Content-Type", "application/json");
        await res.WriteStringAsync(JsonSerializer.Serialize(payload));
        return res;
    }
}

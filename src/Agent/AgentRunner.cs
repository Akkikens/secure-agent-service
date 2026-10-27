using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using SecureAgent.Identity;
using SecureAgent.Security;

namespace SecureAgent;

public sealed record PendingApproval(string RequestId, string Tool, IReadOnlyDictionary<string, object?> Args);

public sealed record TurnResult(string Text, IReadOnlyList<PendingApproval> Pending, AgentSession Session)
{
    public bool NeedsApproval => Pending.Count > 0;
}

/// <summary>
/// One place that runs a turn for a principal: sets the identity context for tool calls, surfaces approval
/// requests to the caller, and pre-checks policy so a user without the scope is never even asked to approve.
/// </summary>
public sealed class AgentRunner(AIAgent agent, IAuditLog audit)
{
    public Task<AgentSession> NewSessionAsync() => agent.CreateSessionAsync().AsTask();

    public async Task<TurnResult> RunAsync(Principal who, string userText, AgentSession session, CancellationToken ct = default)
    {
        using var _ = IdentityContext.Use(who);
        var response = await agent.RunAsync(userText, session, cancellationToken: ct);
        return await Collect(who, response, session, ct);
    }

    public async Task<TurnResult> ResolveAsync(Principal who, AgentSession session, IReadOnlyDictionary<string, bool> decisions, CancellationToken ct = default)
    {
        using var _ = IdentityContext.Use(who);
        var pendingContents = session.PendingApprovals();
        var replies = pendingContents.Select(req =>
        {
            var approved = decisions.GetValueOrDefault(req.RequestId, false);
            var call = (FunctionCallContent)req.ToolCall;
            audit.Record(who.UserId, call.Name, Args(call), approved ? "approved" : "rejected", "by user");
            return new ChatMessage(ChatRole.User, [req.CreateResponse(approved, approved ? "approved by user" : "rejected by user")]);
        }).ToList();
        var response = await agent.RunAsync(replies, session, cancellationToken: ct);
        return await Collect(who, response, session, ct);
    }

    private async Task<TurnResult> Collect(Principal who, AgentResponse response, AgentSession session, CancellationToken ct)
    {
        var requests = response.Messages.SelectMany(m => m.Contents).OfType<ToolApprovalRequestContent>().ToList();
        if (requests.Count == 0)
        {
            session.SetPendingApprovals(Array.Empty<ToolApprovalRequestContent>());
            return new TurnResult(response.Text, Array.Empty<PendingApproval>(), session);
        }

        // Policy pre-check: deny on the caller's behalf when they lack the scope, so the UI never
        // shows an approval prompt for something that would be refused anyway.
        var auto = new List<ChatMessage>();
        var pending = new List<PendingApproval>();
        var stillPending = new List<ToolApprovalRequestContent>();
        foreach (var req in requests)
        {
            var call = (FunctionCallContent)req.ToolCall;
            var policy = PolicyFor(call.Name);
            if (policy is not null && !who.HasScope(policy.Scope))
            {
                audit.Record(who.UserId, call.Name, Args(call), "denied", $"missing scope {policy.Scope} (pre-approval)");
                auto.Add(new ChatMessage(ChatRole.User, [req.CreateResponse(false, $"denied by policy: requires {policy.Scope}")]));
            }
            else
            {
                pending.Add(new PendingApproval(req.RequestId, call.Name, Args(call)));
                stillPending.Add(req);
            }
        }
        if (pending.Count == 0)
        {
            var r = await agent.RunAsync(auto, session, cancellationToken: ct);
            return await Collect(who, r, session, ct);
        }
        session.SetPendingApprovals(stillPending);
        return new TurnResult(response.Text, pending, session);
    }

    private static Dictionary<string, object?> Args(FunctionCallContent call) =>
        call.Arguments is null ? new() : new Dictionary<string, object?>(call.Arguments);

    private ToolPolicy? PolicyFor(string toolName)
    {
        var tools = (agent.GetService(typeof(ChatClientAgent)) as ChatClientAgent)?.ChatClient.GetService<IList<AITool>>()
                    ?? _toolsOverride;
        return tools?.Select(t => (t, p: SecureToolset.PolicyOf(t))).FirstOrDefault(x => x.t.Name == toolName).p;
    }

    private IList<AITool>? _toolsOverride;
    public AgentRunner WithTools(IList<AITool> tools) { _toolsOverride = tools; return this; }
}

internal static class SessionExtensions
{
    private const string Key = "pendingApprovals";
    public static IReadOnlyList<ToolApprovalRequestContent> PendingApprovals(this AgentSession s) =>
        s.StateBag.TryGetValue<List<ToolApprovalRequestContent>>(Key, out var v) && v is not null ? v : Array.Empty<ToolApprovalRequestContent>();
    public static void SetPendingApprovals(this AgentSession s, IEnumerable<ToolApprovalRequestContent> v) =>
        s.StateBag.SetValue(Key, v.ToList());
}

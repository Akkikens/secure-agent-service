using Microsoft.Extensions.AI;
using SecureAgent;
using SecureAgent.Identity;
using SecureAgent.Security;
using SecureAgent.Testing;

namespace Agent.Tests;

internal static class Support
{
    public static Principal Alice(params string[] scopes) => new("alice", new HashSet<string> { "customer" }, scopes.ToHashSet());
    public static Principal Staff(params string[] scopes) => new("sam", new HashSet<string> { "support-staff" }, scopes.ToHashSet());

    public static (AgentRunner runner, JsonlAuditLog audit, ScriptedChatClient chat, OrderStore orders) Build(params ChatResponse[] script)
    {
        var (kb, orders) = Demo.Fixture();
        var audit = new JsonlAuditLog();
        var chat = new ScriptedChatClient(script);
        var tools = SupportAgent.Tools(kb, orders, audit);
        var agent = SupportAgent.Create(chat, kb, orders, audit, telemetry: false);
        return (new AgentRunner(agent, audit).WithTools(tools), audit, chat, orders);
    }

    public static string LastToolResult(ScriptedChatClient chat) =>
        chat.Requests[^1].SelectMany(m => m.Contents).OfType<FunctionResultContent>().Last().Result?.ToString() ?? "";
}

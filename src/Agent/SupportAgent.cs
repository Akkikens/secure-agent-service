using System.ComponentModel;
using Anthropic;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using SecureAgent.Identity;
using SecureAgent.Rag;
using SecureAgent.Security;

namespace SecureAgent;

/// <summary>Demo "order support" domain. Orders are keyed by user so a tool can only ever return the caller's own data.</summary>
public sealed class OrderStore
{
    private readonly Dictionary<string, List<(string Id, string Item, decimal Total, string Status)>> _byUser = new();
    public void Add(string userId, string orderId, string item, decimal total, string status = "delivered")
    {
        if (!_byUser.TryGetValue(userId, out var list)) _byUser[userId] = list = new();
        list.Add((orderId, item, total, status));
    }
    public IReadOnlyList<(string Id, string Item, decimal Total, string Status)> For(string userId) => _byUser.GetValueOrDefault(userId) ?? new();
    public bool Refund(string userId, string orderId)
    {
        var list = _byUser.GetValueOrDefault(userId);
        var i = list?.FindIndex(o => o.Id == orderId) ?? -1;
        if (list is null || i < 0 || list[i].Status == "refunded") return false;
        list[i] = list[i] with { Status = "refunded" };
        return true;
    }
}

public static class SupportAgent
{
    public const string Instructions =
        "You are a customer support agent. Answer only from the search_knowledge tool results and cite each fact with its citation tag, " +
        "e.g. [returns-policy]. If a source is marked stale, say the information may be out of date. " +
        "Use get_my_orders for the user's orders. Only call issue_refund when the user explicitly asks for a refund. " +
        "If a tool reports that an action was denied or failed, tell the user plainly; never pretend it succeeded.";

    public static IList<AITool> Tools(KnowledgeBase kb, OrderStore orders, IAuditLog audit)
    {
        [Description("Search the support knowledge base. Returns snippets with citation tags, update dates and a stale flag.")]
        string SearchKnowledge([Description("What to look up, in the user's words.")] string query) =>
            kb.SearchAsJson(query, IdentityContext.Current);

        [Description("List the current user's orders. Takes no arguments; the user is known from their sign-in.")]
        string GetMyOrders() =>
            System.Text.Json.JsonSerializer.Serialize(orders.For(IdentityContext.Current.UserId).Select(o => new { o.Id, o.Item, o.Total, o.Status }));

        [Description("Refund one of the current user's orders. Side-effecting: requires the user's approval.")]
        string IssueRefund([Description("The order id to refund.")] string orderId) =>
            string.IsNullOrWhiteSpace(orderId) ? throw new ArgumentException("orderId is required")
            : orders.Refund(IdentityContext.Current.UserId, orderId)
                ? $"Refund issued for order {orderId}."
                : $"No refundable order {orderId} belongs to this user.";

        return
        [
            SecureToolset.Secure(AIFunctionFactory.Create(SearchKnowledge, "search_knowledge"), new ToolPolicy("kb:read", SideEffecting: false), audit),
            SecureToolset.Secure(AIFunctionFactory.Create(GetMyOrders, "get_my_orders"), new ToolPolicy("orders:read", SideEffecting: false), audit),
            SecureToolset.Secure(AIFunctionFactory.Create(IssueRefund, "issue_refund"), new ToolPolicy("orders:refund", SideEffecting: true), audit),
        ];
    }

    /// <summary>Build the agent over any <see cref="IChatClient"/> (scripted in tests, Anthropic in production).</summary>
    public static AIAgent Create(IChatClient chat, KnowledgeBase kb, OrderStore orders, IAuditLog audit, bool telemetry = true)
    {
        var agent = new ChatClientAgent(chat, Instructions, name: "support-agent", tools: Tools(kb, orders, audit));
        return telemetry ? agent.AsBuilder().UseOpenTelemetry(sourceName: Telemetry.SourceName).Build() : agent;
    }

    public static AIAgent CreateAnthropic(string apiKey, string model, KnowledgeBase kb, OrderStore orders, IAuditLog audit)
    {
        IChatClient chat = new AnthropicClient { ApiKey = apiKey }.AsIChatClient(model)
            .AsBuilder().UseOpenTelemetry(sourceName: Telemetry.SourceName).Build();
        return Create(chat, kb, orders, audit);
    }
}

public static class Telemetry
{
    public const string SourceName = "SecureAgent";
}

using SecureAgent.Identity;
using SecureAgent.Security;
using SecureAgent.Testing;
using static Agent.Tests.Support;

namespace Agent.Tests;

public class SecurityTests
{
    [Fact]
    public async Task Identity_propagates_to_tools_without_passing_through_the_model()
    {
        var (runner, audit, chat, _) = Build(
            ScriptedChatClient.Call("c1", "get_my_orders", new Dictionary<string, object?>()),
            ScriptedChatClient.Text("You have two orders."));
        var turn = await runner.RunAsync(Alice("orders:read"), "what did I order?", await runner.NewSessionAsync());

        Assert.Equal("You have two orders.", turn.Text);
        var result = LastToolResult(chat);
        Assert.Contains("A-100", result);
        Assert.DoesNotContain("B-200", result); // bob's order never leaves the store
        Assert.DoesNotContain("alice", string.Join(" ", chat.Requests[0].Select(m => m.Text))); // user id was not in the prompt
        Assert.Equal(("alice", "get_my_orders", "allowed"), (audit.Entries[0].UserId, audit.Entries[0].Tool, audit.Entries[0].Decision));
    }

    [Fact]
    public async Task Least_privilege_denies_a_tool_the_caller_lacks_scope_for()
    {
        var (runner, audit, chat, _) = Build(
            ScriptedChatClient.Call("c1", "get_my_orders", new Dictionary<string, object?>()),
            ScriptedChatClient.Text("I can't see your orders."));
        await runner.RunAsync(Alice("kb:read"), "what did I order?", await runner.NewSessionAsync());

        Assert.StartsWith("Denied:", LastToolResult(chat));
        Assert.DoesNotContain("A-100", LastToolResult(chat));
        Assert.Equal("denied", audit.Entries.Single().Decision);
    }

    [Fact]
    public async Task Side_effecting_tool_waits_for_approval_and_runs_only_when_approved()
    {
        var (runner, audit, _, orders) = Build(
            ScriptedChatClient.Call("c1", "issue_refund", new Dictionary<string, object?> { ["orderId"] = "A-100" }),
            ScriptedChatClient.Text("Refunded A-100."));
        var session = await runner.NewSessionAsync();
        var turn = await runner.RunAsync(Alice("orders:refund"), "refund A-100", session);

        Assert.True(turn.NeedsApproval);
        Assert.Equal("issue_refund", turn.Pending.Single().Tool);
        Assert.Equal("delivered", orders.For("alice")[0].Status); // nothing happened yet

        var done = await runner.ResolveAsync(Alice("orders:refund"), session, new Dictionary<string, bool> { [turn.Pending[0].RequestId] = true });
        Assert.Equal("Refunded A-100.", done.Text);
        Assert.Equal("refunded", orders.For("alice")[0].Status);
        Assert.Equal(["approved", "allowed"], audit.Entries.Select(e => e.Decision).ToArray());
    }

    [Fact]
    public async Task Rejected_approval_never_executes_the_tool()
    {
        var (runner, audit, chat, orders) = Build(
            ScriptedChatClient.Call("c1", "issue_refund", new Dictionary<string, object?> { ["orderId"] = "A-100" }),
            ScriptedChatClient.Text("Understood, no refund."));
        var session = await runner.NewSessionAsync();
        var turn = await runner.RunAsync(Alice("orders:refund"), "refund A-100", session);
        await runner.ResolveAsync(Alice("orders:refund"), session, new Dictionary<string, bool> { [turn.Pending[0].RequestId] = false });

        Assert.Equal("delivered", orders.For("alice")[0].Status);
        Assert.DoesNotContain(audit.Entries, e => e.Decision == "allowed");
        Assert.Contains(audit.Entries, e => e.Decision == "rejected");
    }

    [Fact]
    public async Task Caller_without_scope_is_never_asked_to_approve()
    {
        var (runner, audit, chat, orders) = Build(
            ScriptedChatClient.Call("c1", "issue_refund", new Dictionary<string, object?> { ["orderId"] = "A-100" }),
            ScriptedChatClient.Text("You don't have permission to refund."));
        var turn = await runner.RunAsync(Alice("orders:read"), "refund A-100", await runner.NewSessionAsync());

        Assert.False(turn.NeedsApproval);
        Assert.Equal("You don't have permission to refund.", turn.Text);
        Assert.Equal("delivered", orders.For("alice")[0].Status);
        Assert.Contains(audit.Entries, e => e.Decision == "denied" && e.Outcome.Contains("pre-approval"));
    }

    [Fact]
    public async Task Tool_exception_is_fail_safe_and_audited()
    {
        var (runner, audit, chat, _) = Build(
            ScriptedChatClient.Call("c1", "issue_refund", new Dictionary<string, object?> { ["orderId"] = null }),
            ScriptedChatClient.Text("Something went wrong."));
        var session = await runner.NewSessionAsync();
        var turn = await runner.RunAsync(Alice("orders:refund"), "refund", session);
        await runner.ResolveAsync(Alice("orders:refund"), session, new Dictionary<string, bool> { [turn.Pending[0].RequestId] = true });

        Assert.Contains("failed and no changes were made", LastToolResult(chat));
        Assert.Contains(audit.Entries, e => e.Outcome.StartsWith("error"));
    }

    [Fact]
    public void Audit_chain_detects_tampering()
    {
        var log = new JsonlAuditLog();
        log.Record("alice", "t", new Dictionary<string, object?> { ["k"] = "v" }, "allowed", "ok");
        log.Record("alice", "t", new Dictionary<string, object?>(), "denied", "x");
        var entries = log.Entries.ToList();
        Assert.Equal(-1, JsonlAuditLog.Verify(entries));
        entries[0] = entries[0] with { Decision = "denied" };
        Assert.Equal(0, JsonlAuditLog.Verify(entries));
        Assert.DoesNotContain("v", entries[0].ArgsHash); // argument values are hashed, not stored
    }

    [Fact]
    public async Task Jwt_round_trip_carries_roles_and_scopes()
    {
        var jwt = new JwtIdentity("0123456789abcdef0123456789abcdef");
        var token = jwt.Mint("alice", ["customer"], ["kb:read", "orders:read"]);
        var p = await jwt.ValidateAsync(token);
        Assert.NotNull(p);
        Assert.Equal("alice", p!.UserId);
        Assert.True(p.HasScope("orders:read") && !p.HasScope("orders:refund"));
        Assert.Null(await new JwtIdentity("ffffffffffffffffffffffffffffffff").ValidateAsync(token)); // wrong key
    }
}

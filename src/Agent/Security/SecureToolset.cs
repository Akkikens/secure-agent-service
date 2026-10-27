using Microsoft.Extensions.AI;
using SecureAgent.Identity;

namespace SecureAgent.Security;

public sealed class PolicyDeniedException(string message) : Exception(message);

/// <summary>What a tool needs before it may run. Side-effecting tools also need user approval.</summary>
public sealed record ToolPolicy(string Scope, bool SideEffecting);

/// <summary>
/// Least-privilege tool access: the wrapped function runs only if the propagated principal holds the
/// tool's scope. Decisions and outcomes go to the audit log. Failures become tool results, not crashes.
/// </summary>
public sealed class ScopedAIFunction : DelegatingAIFunction
{
    private readonly ToolPolicy _policy;
    private readonly IAuditLog _audit;

    public ScopedAIFunction(AIFunction inner, ToolPolicy policy, IAuditLog audit) : base(inner)
    {
        _policy = policy;
        _audit = audit;
    }

    public ToolPolicy Policy => _policy;

    protected override async ValueTask<object?> InvokeCoreAsync(AIFunctionArguments arguments, CancellationToken cancellationToken)
    {
        var who = IdentityContext.Current;
        var args = arguments.ToDictionary(kv => kv.Key, kv => kv.Value);
        if (!who.HasScope(_policy.Scope))
        {
            _audit.Record(who.UserId, Name, args, "denied", $"missing scope {_policy.Scope}");
            return $"Denied: this action requires the '{_policy.Scope}' permission, which the current user does not have.";
        }
        try
        {
            var result = await base.InvokeCoreAsync(arguments, cancellationToken);
            _audit.Record(who.UserId, Name, args, "allowed", "ok");
            return result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // fail-safe: the model sees a bounded error string; the real exception stays in the audit log
            _audit.Record(who.UserId, Name, args, "allowed", $"error {ex.GetType().Name}: {ex.Message}");
            return $"The '{Name}' tool failed and no changes were made. Tell the user and do not retry automatically.";
        }
    }
}

public static class SecureToolset
{
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<AITool, ToolPolicy> Policies = new();

    /// <summary>Wrap a function with its policy: scope check always; approval gate when side-effecting.</summary>
    public static AITool Secure(AIFunction function, ToolPolicy policy, IAuditLog audit)
    {
        AIFunction scoped = new ScopedAIFunction(function, policy, audit);
        AITool tool = policy.SideEffecting ? new ApprovalRequiredAIFunction(scoped) : scoped;
        Policies.Add(tool, policy);
        return tool;
    }

    public static ToolPolicy? PolicyOf(AITool tool) => Policies.TryGetValue(tool, out var p) ? p : null;
}

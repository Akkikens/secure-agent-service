using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.AI;
using SecureAgent.Identity;
using SecureAgent.Rag;
using SecureAgent.Security;

namespace SecureAgent.Eval;

/// <summary>One golden case: who asks what, the recorded model turns, and what a correct answer must satisfy.</summary>
public sealed class GoldenCase
{
    public required string Id { get; init; }
    public required string Cassette { get; init; }
    public required string UserId { get; init; }
    public string[] Roles { get; init; } = [];
    public string[] Scopes { get; init; } = [];
    public required string Prompt { get; init; }
    public Dictionary<string, bool> Approvals { get; init; } = new();
    public Expect Expect { get; init; } = new();
}

public sealed class Expect
{
    public string[] AnswerContains { get; init; } = [];
    public string[] AnswerNotContains { get; init; } = [];
    public string[] Citations { get; init; } = [];
    public string[] ToolsCalled { get; init; } = [];
    public int? Denied { get; init; }
    public int? PendingApprovals { get; init; }
    /// <summary>Rubric criteria the judge model scores 0-1 each; the case needs the average at or above RubricThreshold.</summary>
    public string[] Rubric { get; init; } = [];
    public double RubricThreshold { get; init; } = 0.8;
}

public sealed record CaseResult(string Id, string Status, string Reason, double? RubricScore = null);

/// <summary>
/// Scores an answer against a rubric with a judge model. Deterministic checks run first and are cheap;
/// the rubric only runs when the case asks for it. The judge is any IChatClient, so it is replayable too.
/// </summary>
public sealed class RubricJudge(IChatClient judge)
{
    private sealed record Verdict(Dictionary<string, double> Scores, string Notes);

    public async Task<(double Score, string Notes)> ScoreAsync(string prompt, string answer, string[] rubric, CancellationToken ct = default)
    {
        var criteria = string.Join("\n", rubric.Select((r, i) => $"{i + 1}. {r}"));
        var ask = $"Score the ANSWER against each criterion from 0 to 1. Reply with JSON only: {{\"scores\":{{\"1\":0.0,...}},\"notes\":\"...\"}}\n\nCRITERIA:\n{criteria}\n\nUSER PROMPT:\n{prompt}\n\nANSWER:\n{answer}";
        var r = await judge.GetResponseAsync([new ChatMessage(ChatRole.User, ask)], cancellationToken: ct);
        var text = r.Text;
        var start = text.IndexOf('{'); var end = text.LastIndexOf('}');
        if (start < 0 || end <= start) return (0, "judge returned no JSON");
        var v = JsonSerializer.Deserialize<Verdict>(text[start..(end + 1)], Json);
        if (v is null || v.Scores.Count == 0) return (0, "judge JSON unparseable");
        return (Math.Round(v.Scores.Values.Average(), 3), v.Notes);
    }

    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };
}

public static class EvalRunner
{
    public static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public static List<GoldenCase> Load(string dir) =>
        Directory.GetFiles(dir, "*.json").Where(f => !f.EndsWith("baseline.json")).OrderBy(f => f)
            .Select(f => JsonSerializer.Deserialize<GoldenCase>(File.ReadAllText(f), Json)!).ToList();

    public static async Task<CaseResult> RunCaseAsync(GoldenCase c, string casesDir, Func<(KnowledgeBase kb, OrderStore orders)> fixture, RubricJudge? judge)
    {
        var (kb, orders) = fixture();
        var audit = new JsonlAuditLog();
        var who = new Principal(c.UserId, c.Roles.ToHashSet(), c.Scopes.ToHashSet());
        var cassette = Path.Combine(casesDir, c.Cassette);
        try
        {
            var agent = SupportAgent.Create(new ReplayChatClient(cassette), kb, orders, audit, telemetry: false);
            var runner = new AgentRunner(agent, audit).WithTools(SupportAgent.Tools(kb, orders, new JsonlAuditLog()));
            var session = await runner.NewSessionAsync();
            var turn = await runner.RunAsync(who, c.Prompt, session);
            var pendingSeen = turn.Pending.Count;
            if (turn.NeedsApproval && c.Approvals.Count > 0)
                turn = await runner.ResolveAsync(who, session, turn.Pending.ToDictionary(p => p.RequestId, p => c.Approvals.GetValueOrDefault(p.Tool, false)));

            var problems = new List<string>();
            var e = c.Expect;
            foreach (var s in e.AnswerContains) if (!turn.Text.Contains(s, StringComparison.OrdinalIgnoreCase)) problems.Add($"answer lacks '{s}'");
            foreach (var s in e.AnswerNotContains) if (turn.Text.Contains(s, StringComparison.OrdinalIgnoreCase)) problems.Add($"answer must not contain '{s}'");
            foreach (var cite in e.Citations) if (!turn.Text.Contains($"[{cite}]")) problems.Add($"missing citation [{cite}]");
            var called = audit.Entries.Where(a => a.Decision is "allowed" or "denied").Select(a => a.Tool).ToList();
            if (e.ToolsCalled.Length > 0 && !called.SequenceEqual(e.ToolsCalled)) problems.Add($"tools {string.Join(",", called)} != {string.Join(",", e.ToolsCalled)}");
            var denied = audit.Entries.Count(a => a.Decision == "denied");
            if (e.Denied is { } d && denied != d) problems.Add($"denied {denied} != {d}");
            if (e.PendingApprovals is { } p && pendingSeen != p) problems.Add($"pending approvals {pendingSeen} != {p}");

            double? rubricScore = null;
            if (e.Rubric.Length > 0 && judge is not null)
            {
                var (score, notes) = await judge.ScoreAsync(c.Prompt, turn.Text, e.Rubric);
                rubricScore = score;
                if (score < e.RubricThreshold) problems.Add($"rubric {score} < {e.RubricThreshold} ({notes})");
            }
            return new CaseResult(c.Id, problems.Count == 0 ? "pass" : "fail", string.Join("; ", problems), rubricScore);
        }
        catch (CassetteDriftException ex) { return new CaseResult(c.Id, "fail", "cassette drift: " + ex.Message); }
    }

    /// <summary>CI gate: any case that passed in the baseline must still pass; new failures without a baseline fail too.</summary>
    public static (bool Ok, List<string> Notes) Gate(IReadOnlyList<CaseResult> results, string[]? baselinePassed)
    {
        var notes = new List<string>();
        if (baselinePassed is null)
            return (results.All(r => r.Status != "fail"), results.Where(r => r.Status == "fail").Select(r => $"FAIL {r.Id}: {r.Reason}").ToList());
        var ok = true;
        foreach (var id in baselinePassed)
        {
            var r = results.FirstOrDefault(x => x.Id == id);
            if (r is null) { ok = false; notes.Add($"REGRESSION {id}: case missing"); }
            else if (r.Status == "fail") { ok = false; notes.Add($"REGRESSION {id}: {r.Reason}"); }
        }
        foreach (var r in results.Where(r => r.Status == "pass" && !baselinePassed.Contains(r.Id))) notes.Add($"NEW PASS {r.Id}");
        return (ok, notes);
    }
}

using Microsoft.Extensions.AI;
using SecureAgent;
using SecureAgent.Eval;
using SecureAgent.Rag;
using SecureAgent.Security;
using SecureAgent.Testing;
using static Agent.Tests.Support;

namespace Agent.Tests;

public class RagAndEvalTests
{
    [Fact]
    public void Acl_hides_internal_documents_from_customers_before_ranking()
    {
        var (kb, _) = Demo.Fixture();
        var asCustomer = kb.Search("escalate chargebacks fraud", Alice());
        var asStaff = kb.Search("escalate chargebacks fraud", Staff());
        Assert.DoesNotContain(asCustomer, h => h.Source == "internal-escalation");
        Assert.Contains(asStaff, h => h.Source == "internal-escalation");
    }

    [Fact]
    public void Results_carry_citations_and_flag_stale_sources()
    {
        var (kb, _) = Demo.Fixture();
        var hits = kb.Search("how long does express shipping take", Alice());
        var top = hits.First();
        Assert.Equal("[shipping-faq]", top.Citation);
        Assert.True(top.Stale, "shipping-faq is 400 days old and must be flagged");
        Assert.False(kb.Search("return for refund", Alice()).First().Stale);
    }

    [Fact]
    public void Reranking_prefers_the_fresher_doc_on_a_near_tie()
    {
        var kb = new KnowledgeBase { Now = () => Demo.Today };
        kb.Add(new Document("old", "old-doc", "Refund timing: refunds take ten business days.", Demo.Today.AddDays(-900), new HashSet<string>()));
        kb.Add(new Document("new", "new-doc", "Refund timing: refunds take five business days.", Demo.Today.AddDays(-10), new HashSet<string>()));
        Assert.Equal("new-doc", kb.Search("refund timing business days", Alice()).First().Source);
    }

    [Fact]
    public async Task Agent_answer_is_grounded_and_cited()
    {
        var (runner, _, chat, _) = Build(
            ScriptedChatClient.Call("c1", "search_knowledge", new Dictionary<string, object?> { ["query"] = "return window" }),
            ScriptedChatClient.Text("You can return items within 30 days of delivery [returns-policy]."));
        var turn = await runner.RunAsync(Alice("kb:read"), "how long do I have to return?", await runner.NewSessionAsync());
        Assert.Contains("[returns-policy]", turn.Text);
        Assert.Contains("\"citation\":\"[returns-policy]\"", LastToolResult(chat));
    }

    [Fact]
    public async Task Replay_reproduces_a_recorded_run_and_detects_drift()
    {
        var path = Path.GetTempFileName();
        var (kb, orders) = Demo.Fixture();
        var scripted = new ScriptedChatClient([
            ScriptedChatClient.Call("c1", "search_knowledge", new Dictionary<string, object?> { ["query"] = "return window" }),
            ScriptedChatClient.Text("30 days [returns-policy].")]);
        var rec = SupportAgent.Create(new RecordingChatClient(scripted, path), kb, orders, new JsonlAuditLog(), telemetry: false);
        var r1 = new AgentRunner(rec, new JsonlAuditLog());
        var t1 = await r1.RunAsync(Alice("kb:read"), "how long do I have to return?", await r1.NewSessionAsync());
        Assert.Equal(2, File.ReadLines(path).Count());

        var (kb2, orders2) = Demo.Fixture();
        var rep = SupportAgent.Create(new ReplayChatClient(path), kb2, orders2, new JsonlAuditLog(), telemetry: false);
        var r2 = new AgentRunner(rep, new JsonlAuditLog());
        var t2 = await r2.RunAsync(Alice("kb:read"), "how long do I have to return?", await r2.NewSessionAsync());
        Assert.Equal(t1.Text, t2.Text);

        var r3 = new AgentRunner(SupportAgent.Create(new ReplayChatClient(path), kb2, orders2, new JsonlAuditLog(), telemetry: false), new JsonlAuditLog());
        await Assert.ThrowsAsync<CassetteDriftException>(() => r3.RunAsync(Alice("kb:read"), "a different question", r3.NewSessionAsync().Result));
    }

    [Fact]
    public async Task Rubric_judge_parses_scores_and_gate_flags_regressions()
    {
        var judge = new RubricJudge(new ScriptedChatClient([ScriptedChatClient.Text("Sure: {\"scores\":{\"1\":1.0,\"2\":0.5},\"notes\":\"missed the stale warning\"}")]));
        var (score, notes) = await judge.ScoreAsync("q", "a", ["cites a source", "warns when stale"]);
        Assert.Equal(0.75, score);
        Assert.Contains("stale", notes);

        var (ok, _) = EvalRunner.Gate([new CaseResult("a", "pass", ""), new CaseResult("b", "fail", "x")], ["a"]);
        Assert.True(ok, "a known failure outside the baseline is not a regression");
        var (bad, notes2) = EvalRunner.Gate([new CaseResult("a", "fail", "drift")], ["a"]);
        Assert.False(bad);
        Assert.Contains(notes2, n => n.StartsWith("REGRESSION a"));
    }

    [Fact]
    public async Task Golden_cases_in_repo_pass_against_their_cassettes()
    {
        var dir = FindCasesDir();
        var cases = EvalRunner.Load(dir);
        Assert.NotEmpty(cases);
        foreach (var c in cases)
        {
            var r = await EvalRunner.RunCaseAsync(c, dir, Demo.Fixture, judge: null);
            Assert.True(r.Status == "pass", $"{c.Id}: {r.Reason}");
        }
    }

    internal static string FindCasesDir()
    {
        var d = AppContext.BaseDirectory;
        while (d is not null && !Directory.Exists(Path.Combine(d, "evals", "cases"))) d = Path.GetDirectoryName(d);
        return Path.Combine(d ?? throw new DirectoryNotFoundException("evals/cases"), "evals", "cases");
    }
}

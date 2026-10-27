using System.Text.Json;
using System.Text.RegularExpressions;
using SecureAgent.Identity;

namespace SecureAgent.Rag;

public sealed record Document(string Id, string Source, string Text, DateTimeOffset UpdatedAt, IReadOnlySet<string> AllowedRoles);

public sealed record Hit(string DocId, string Source, string Snippet, double Score, DateTimeOffset UpdatedAt, bool Stale)
{
    public string Citation => $"[{Source}]";
}

/// <summary>
/// Small in-memory retrieval layer with the properties a grounded support agent needs:
/// access control (ACL per document, filtered by the caller's roles before scoring),
/// ranking (BM25 then a reranking pass), citations, and knowledge freshness.
/// </summary>
public sealed class KnowledgeBase
{
    private readonly List<Document> _docs = new();
    private readonly Dictionary<string, Dictionary<string, int>> _tf = new();
    private readonly Dictionary<string, int> _df = new();
    private double _avgLen;

    public TimeSpan MaxAge { get; init; } = TimeSpan.FromDays(180);
    public Func<DateTimeOffset> Now { get; init; } = () => DateTimeOffset.UtcNow;
    public int Count => _docs.Count;

    public void Add(Document doc)
    {
        _docs.Add(doc);
        var tf = Tokenize(doc.Text).GroupBy(t => t).ToDictionary(g => g.Key, g => g.Count());
        _tf[doc.Id] = tf;
        foreach (var term in tf.Keys) _df[term] = _df.GetValueOrDefault(term) + 1;
        _avgLen = _tf.Values.Average(t => t.Values.Sum());
    }

    /// <summary>Data-boundary enforcement happens here, before ranking: a caller never sees a document their roles don't cover.</summary>
    public IReadOnlyList<Hit> Search(string query, Principal who, int topK = 3)
    {
        var visible = _docs.Where(d => d.AllowedRoles.Count == 0 || who.HasAnyRole(d.AllowedRoles)).ToList();
        if (visible.Count == 0) return Array.Empty<Hit>();
        var q = Tokenize(query).Distinct().ToList();
        var n = _docs.Count;
        var scored = visible.Select(d =>
        {
            var tf = _tf[d.Id];
            var len = tf.Values.Sum();
            double score = 0;
            foreach (var term in q)
            {
                if (!tf.TryGetValue(term, out var f)) continue;
                var idf = Math.Log(1 + (n - _df[term] + 0.5) / (_df[term] + 0.5));
                score += idf * (f * 2.2) / (f + 1.2 * (0.25 + 0.75 * len / _avgLen));
            }
            return (doc: d, bm25: score);
        }).Where(x => x.bm25 > 0).OrderByDescending(x => x.bm25).Take(topK * 3).ToList();

        // rerank: exact-phrase bonus and a mild recency bonus, so a fresher doc wins a near tie
        var now = Now();
        var reranked = scored.Select(x =>
        {
            var phrase = x.doc.Text.Contains(query, StringComparison.OrdinalIgnoreCase) ? 1.0 : 0.0;
            var ageDays = Math.Max(0, (now - x.doc.UpdatedAt).TotalDays);
            var recency = 0.3 * Math.Exp(-ageDays / 365.0);
            return (x.doc, score: x.bm25 + phrase + recency);
        }).OrderByDescending(x => x.score).Take(topK);

        return reranked.Select(x => new Hit(x.doc.Id, x.doc.Source, Snippet(x.doc.Text, q), Math.Round(x.score, 3),
            x.doc.UpdatedAt, now - x.doc.UpdatedAt > MaxAge)).ToList();
    }

    public string SearchAsJson(string query, Principal who, int topK = 3) =>
        JsonSerializer.Serialize(Search(query, who, topK).Select(h => new
        {
            citation = h.Citation, snippet = h.Snippet, updated = h.UpdatedAt.ToString("yyyy-MM-dd"),
            stale = h.Stale, note = h.Stale ? "This source is older than the freshness window; say so if you rely on it." : null,
        }));

    private static string Snippet(string text, List<string> q)
    {
        var sentences = Regex.Split(text, @"(?<=[.!?])\s+");
        var best = sentences.OrderByDescending(s => Tokenize(s).Count(q.Contains)).First();
        return best.Length > 240 ? best[..240] + "…" : best;
    }

    public static List<string> Tokenize(string s) =>
        Regex.Matches(s.ToLowerInvariant(), @"[a-z0-9]+").Select(m => Stem(m.Value)).Where(t => t.Length > 1 && !Stop.Contains(t)).ToList();

    /// <summary>Light suffix stripping so "returned", "returns" and "return" rank together. Not a full stemmer.</summary>
    private static string Stem(string t)
    {
        if (t.Length <= 4) return t;
        foreach (var suf in new[] { "ing", "ed", "es", "s" })
            if (t.EndsWith(suf) && t.Length - suf.Length >= 3) return t[..^suf.Length];
        return t;
    }

    private static readonly HashSet<string> Stop = new() { "the", "a", "an", "and", "or", "of", "to", "in", "is", "it", "for", "on", "with", "do", "how", "my", "can", "what", "be", "i" };
}

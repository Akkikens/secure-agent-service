using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecureAgent.Security;

public sealed record AuditEntry(
    DateTimeOffset At, string UserId, string Tool, string ArgsHash, string Decision, string Outcome, string PrevHash, string Hash);

/// <summary>Every tool decision and outcome is recorded with who, what, and why.</summary>
public interface IAuditLog
{
    AuditEntry Record(string userId, string tool, IReadOnlyDictionary<string, object?> args, string decision, string outcome);
    IReadOnlyList<AuditEntry> Entries { get; }
}

/// <summary>
/// Append-only JSONL log where each entry hashes the previous one, so a removed or edited
/// line breaks the chain. <see cref="Verify"/> walks it. Argument values are hashed, not stored,
/// so the log never holds user data in the clear.
/// </summary>
public sealed class JsonlAuditLog : IAuditLog
{
    private readonly string? _path;
    private readonly List<AuditEntry> _entries = new();
    private readonly object _lock = new();

    public JsonlAuditLog(string? path = null)
    {
        _path = path;
        if (path is not null && File.Exists(path))
            _entries.AddRange(File.ReadLines(path).Where(l => l.Length > 0).Select(l => JsonSerializer.Deserialize<AuditEntry>(l)!));
    }

    public IReadOnlyList<AuditEntry> Entries { get { lock (_lock) return _entries.ToList(); } }

    public AuditEntry Record(string userId, string tool, IReadOnlyDictionary<string, object?> args, string decision, string outcome)
    {
        lock (_lock)
        {
            var prev = _entries.Count == 0 ? "genesis" : _entries[^1].Hash;
            var argsHash = Sha(JsonSerializer.Serialize(args.OrderBy(k => k.Key).ToDictionary(k => k.Key, k => k.Value?.ToString())));
            var at = DateTimeOffset.UtcNow;
            var hash = Sha($"{prev}|{at:O}|{userId}|{tool}|{argsHash}|{decision}|{outcome}");
            var entry = new AuditEntry(at, userId, tool, argsHash, decision, outcome, prev, hash);
            _entries.Add(entry);
            if (_path is not null) File.AppendAllText(_path, JsonSerializer.Serialize(entry) + "\n");
            return entry;
        }
    }

    /// <summary>Returns the index of the first broken link, or -1 if the chain is intact.</summary>
    public static int Verify(IReadOnlyList<AuditEntry> entries)
    {
        var prev = "genesis";
        for (var i = 0; i < entries.Count; i++)
        {
            var e = entries[i];
            var expected = Sha($"{prev}|{e.At:O}|{e.UserId}|{e.Tool}|{e.ArgsHash}|{e.Decision}|{e.Outcome}");
            if (e.PrevHash != prev || e.Hash != expected) return i;
            prev = e.Hash;
        }
        return -1;
    }

    private static string Sha(string s) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)))[..32];
}

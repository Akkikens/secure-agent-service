using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.AI;

namespace SecureAgent.Eval;

public sealed class CassetteDriftException(string message) : Exception(message);

/// <summary>Stable fingerprint of a model request: messages (role + text + tool calls/results) and the tool names offered.</summary>
public static class RequestKey
{
    public static string Of(IEnumerable<ChatMessage> messages, ChatOptions? options)
    {
        var sb = new StringBuilder();
        foreach (var m in messages)
        {
            sb.Append(m.Role.Value).Append('|');
            foreach (var c in m.Contents)
                sb.Append(c switch
                {
                    TextContent t => "T:" + t.Text,
                    FunctionCallContent f => "C:" + f.Name + ":" + JsonSerializer.Serialize(f.Arguments),
                    FunctionResultContent r => "R:" + r.Result?.ToString(),
                    ToolApprovalResponseContent a => "A:" + a.Approved,
                    _ => c.GetType().Name,
                }).Append('|');
            sb.Append('\n');
        }
        sb.Append("tools:").AppendJoin(',', options?.Tools?.Select(t => t.Name) ?? Array.Empty<string>());
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())))[..16];
    }
}

internal sealed record CassetteEntry(string Key, string Text, List<CassetteCall> Calls);
internal sealed record CassetteCall(string Id, string Name, Dictionary<string, object?> Args);

/// <summary>Wraps a real client and appends every (request key, response) to a JSONL cassette.</summary>
public sealed class RecordingChatClient(IChatClient inner, string path) : DelegatingChatClient(inner)
{
    public override async Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        var list = messages.ToList();
        var response = await base.GetResponseAsync(list, options, cancellationToken);
        var entry = new CassetteEntry(RequestKey.Of(list, options), response.Text,
            response.Messages.SelectMany(m => m.Contents).OfType<FunctionCallContent>()
                .Select(f => new CassetteCall(f.CallId, f.Name, new(f.Arguments ?? new Dictionary<string, object?>()))).ToList());
        await File.AppendAllTextAsync(path, JsonSerializer.Serialize(entry) + "\n", cancellationToken);
        return response;
    }
}

/// <summary>Serves a cassette with no network; a request that differs from what was recorded is drift, not a silent pass.</summary>
public sealed class ReplayChatClient : IChatClient
{
    private readonly Queue<CassetteEntry> _entries;
    private int _turn;

    public ReplayChatClient(string path) =>
        _entries = new Queue<CassetteEntry>(File.ReadLines(path).Where(l => l.Length > 0).Select(l => JsonSerializer.Deserialize<CassetteEntry>(l)!));

    public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        var list = messages.ToList();
        if (_entries.Count == 0) throw new CassetteDriftException($"cassette exhausted after {_turn} turns: the agent made an extra model call");
        var entry = _entries.Dequeue();
        var key = RequestKey.Of(list, options);
        if (key != entry.Key)
            throw new CassetteDriftException($"turn {_turn}: request {key} != recorded {entry.Key} (prompt, tool set or tool output changed; re-record if intended)");
        _turn++;
        var contents = new List<AIContent>();
        if (entry.Text.Length > 0) contents.Add(new TextContent(entry.Text));
        contents.AddRange(entry.Calls.Select(c => new FunctionCallContent(c.Id, c.Name, Normalize(c.Args))));
        return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, contents)));
    }

    private static Dictionary<string, object?> Normalize(Dictionary<string, object?> args) =>
        args.ToDictionary(kv => kv.Key, kv => kv.Value is JsonElement e ? (object?)(e.ValueKind == JsonValueKind.String ? e.GetString() : e.ToString()) : kv.Value);

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var r = await GetResponseAsync(messages, options, cancellationToken);
        foreach (var u in r.ToChatResponseUpdates()) yield return u;
    }

    public object? GetService(Type serviceType, object? serviceKey = null) => serviceType.IsInstanceOfType(this) ? this : null;
    public void Dispose() { }
}

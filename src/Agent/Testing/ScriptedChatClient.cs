using System.Runtime.CompilerServices;
using Microsoft.Extensions.AI;

namespace SecureAgent.Testing;

/// <summary>
/// Deterministic <see cref="IChatClient"/>: returns scripted responses in order, one per model call.
/// Used by tests, the demo CLI and as the recorded "model" in eval cassettes.
/// </summary>
public sealed class ScriptedChatClient : IChatClient
{
    private readonly Queue<ChatResponse> _script;
    public List<IReadOnlyList<ChatMessage>> Requests { get; } = new();

    public ScriptedChatClient(IEnumerable<ChatResponse> script) => _script = new Queue<ChatResponse>(script);

    public static ChatResponse Text(string text) => new(new ChatMessage(ChatRole.Assistant, text));

    public static ChatResponse Call(string callId, string name, IDictionary<string, object?> args, string? text = null)
    {
        var contents = new List<AIContent>();
        if (text is not null) contents.Add(new TextContent(text));
        contents.Add(new FunctionCallContent(callId, name, args));
        return new ChatResponse(new ChatMessage(ChatRole.Assistant, contents));
    }

    public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        Requests.Add(messages.ToList());
        if (_script.Count == 0) return Task.FromResult(Text("(script exhausted)"));
        return Task.FromResult(_script.Dequeue());
    }

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var r = await GetResponseAsync(messages, options, cancellationToken);
        foreach (var u in r.ToChatResponseUpdates()) yield return u;
    }

    public object? GetService(Type serviceType, object? serviceKey = null) => serviceType.IsInstanceOfType(this) ? this : null;
    public void Dispose() { }
}

using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenTelemetry.Trace;
using SecureAgent;
using SecureAgent.Identity;
using SecureAgent.Security;
using SecureAgent.Testing;

var builder = FunctionsApplication.CreateBuilder(args);
builder.ConfigureFunctionsWebApplication();

builder.Services.AddOpenTelemetry().WithTracing(t => t.AddSource(Telemetry.SourceName).AddConsoleExporter());

builder.Services.AddSingleton(new JwtIdentity(Environment.GetEnvironmentVariable("AGENT_JWT_KEY") ?? "dev-only-key-change-me-0123456789abcdef"));
builder.Services.AddSingleton<IAuditLog>(new JsonlAuditLog(Environment.GetEnvironmentVariable("AGENT_AUDIT_PATH") ?? "audit.jsonl"));
builder.Services.AddSingleton(sp =>
{
    var (kb, orders) = Demo.Fixture();
    var audit = sp.GetRequiredService<IAuditLog>();
    var apiKey = Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY");
    // Without a key the host still runs, with a fixed scripted model, so the HTTP contract can be exercised offline.
    var agent = apiKey is null
        ? SupportAgent.Create(new ScriptedChatClient([ScriptedChatClient.Text("(no ANTHROPIC_API_KEY set: scripted reply)")]), kb, orders, audit)
        : SupportAgent.CreateAnthropic(apiKey, Environment.GetEnvironmentVariable("ANTHROPIC_CHAT_MODEL") ?? "claude-sonnet-5-5", kb, orders, audit);
    return new AgentRunner(agent, audit).WithTools(SupportAgent.Tools(kb, orders, new JsonlAuditLog()));
});

builder.Build().Run();

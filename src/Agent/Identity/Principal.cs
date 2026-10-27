using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SecureAgent.Identity;

/// <summary>The caller's identity as the agent and every tool see it.</summary>
public sealed record Principal(string UserId, IReadOnlySet<string> Roles, IReadOnlySet<string> Scopes)
{
    public bool HasScope(string scope) => Scopes.Contains(scope);
    public bool HasAnyRole(IEnumerable<string> roles) => roles.Any(Roles.Contains);
    public static Principal Anonymous { get; } = new("anonymous", new HashSet<string>(), new HashSet<string>());
}

/// <summary>
/// Identity propagation: the principal validated at the service edge flows to every tool
/// invocation on the same logical call chain, without being passed through the model.
/// </summary>
public static class IdentityContext
{
    private static readonly AsyncLocal<Principal?> Current_ = new();
    public static Principal Current => Current_.Value ?? Principal.Anonymous;

    public static IDisposable Use(Principal principal)
    {
        var previous = Current_.Value;
        Current_.Value = principal;
        return new Restore(() => Current_.Value = previous);
    }

    private sealed class Restore(Action undo) : IDisposable { public void Dispose() => undo(); }
}

/// <summary>HS256 JWT mint/validate for the dev host. Swap the key source for an identity provider's JWKS in production.</summary>
public sealed class JwtIdentity(string signingKey, string issuer = "secure-agent-service", string audience = "agent")
{
    private readonly SymmetricSecurityKey _key = new(Encoding.UTF8.GetBytes(signingKey.Length >= 32 ? signingKey
        : throw new ArgumentException("signing key must be at least 32 bytes")));
    private readonly JsonWebTokenHandler _handler = new();

    public string Mint(string userId, IEnumerable<string> roles, IEnumerable<string> scopes, TimeSpan? lifetime = null)
    {
        var claims = new List<Claim> { new("sub", userId), new("scope", string.Join(' ', scopes)) };
        claims.AddRange(roles.Select(r => new Claim("role", r)));
        return _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer, Audience = audience, Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromHours(1)),
            SigningCredentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256),
        });
    }

    public async Task<Principal?> ValidateAsync(string token)
    {
        var result = await _handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = issuer, ValidAudience = audience, IssuerSigningKey = _key,
            ClockSkew = TimeSpan.FromSeconds(30),
        });
        if (!result.IsValid) return null;
        var id = result.ClaimsIdentity;
        var sub = id.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(sub)) return null;
        var roles = id.FindAll("role").Select(c => c.Value).ToHashSet();
        var scopes = (id.FindFirst("scope")?.Value ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
        return new Principal(sub, roles, scopes);
    }
}

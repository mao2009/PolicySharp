using System.Text.Json;
using System.Text.Json.Serialization;

namespace PolicySharp.Core;

public sealed class PolicyDocument
{
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("mode")]
    public string Mode { get; set; } = "default-deny";

    [JsonPropertyName("scopes")]
    public IReadOnlyList<PolicyScope> Scopes { get; set; } = Array.Empty<PolicyScope>();

    [JsonPropertyName("dependencies")]
    public PolicyDependencyPolicy Dependencies { get; set; } = new();

    public static PolicyDocument Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new ArgumentException("Policy JSON must not be empty.", nameof(json));
        }

        var document = JsonSerializer.Deserialize<PolicyDocument>(json, SerializerOptions)
            ?? throw new JsonException("Policy document was empty.");

        document.Validate();
        return document;
    }

    public void Validate()
    {
        if (Version != 1)
        {
            throw new JsonException($"Unsupported PolicySharp policy version: {Version}.");
        }

        if (!string.Equals(Mode, "default-deny", StringComparison.OrdinalIgnoreCase))
        {
            throw new JsonException("PolicySharp v1 only supports mode 'default-deny'.");
        }

        if (Scopes is null)
        {
            throw new JsonException("Property 'scopes' is required.");
        }

        Dependencies ??= new PolicyDependencyPolicy();
        Dependencies.Allow ??= new PolicyDependencyAccess();
        Dependencies.Deny ??= new PolicyDependencyAccess();

        var ids = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < Scopes.Count; index++)
        {
            var scope = Scopes[index]
                ?? throw new JsonException($"Scope at index {index} must not be null.");

            if (string.IsNullOrWhiteSpace(scope.Id))
            {
                throw new JsonException($"Scope at index {index} must have a non-empty 'id'.");
            }

            if (!ids.Add(scope.Id))
            {
                throw new JsonException($"Duplicate scope id '{scope.Id}'.");
            }

            if (scope.Match is null || string.IsNullOrWhiteSpace(scope.Match.Namespace))
            {
                throw new JsonException($"Scope '{scope.Id}' must define match.namespace.");
            }

            scope.Allow ??= new PolicyAccess();
            scope.Deny ??= new PolicyAccess();
        }
    }

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };
}

public sealed class PolicyScope
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("match")]
    public PolicyMatch Match { get; set; } = new();

    [JsonPropertyName("allow")]
    public PolicyAccess Allow { get; set; } = new();

    [JsonPropertyName("deny")]
    public PolicyAccess Deny { get; set; } = new();
}

public sealed class PolicyMatch
{
    [JsonPropertyName("namespace")]
    public string Namespace { get; set; } = string.Empty;
}

public sealed class PolicyAccess
{
    [JsonPropertyName("namespaces")]
    public IReadOnlyList<string> Namespaces { get; set; } = Array.Empty<string>();

    [JsonPropertyName("capabilities")]
    public IReadOnlyList<string> Capabilities { get; set; } = Array.Empty<string>();

    [JsonPropertyName("symbols")]
    public IReadOnlyList<string> Symbols { get; set; } = Array.Empty<string>();
}


public sealed class PolicyDependencyPolicy
{
    [JsonPropertyName("allow")]
    public PolicyDependencyAccess Allow { get; set; } = new();

    [JsonPropertyName("deny")]
    public PolicyDependencyAccess Deny { get; set; } = new();
}

public sealed class PolicyDependencyAccess
{
    [JsonPropertyName("packages")]
    public IReadOnlyList<string> Packages { get; set; } = Array.Empty<string>();

    [JsonPropertyName("projects")]
    public IReadOnlyList<string> Projects { get; set; } = Array.Empty<string>();
}

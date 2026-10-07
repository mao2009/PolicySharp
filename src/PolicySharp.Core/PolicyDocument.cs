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

    public static PolicyDocument Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new ArgumentException("Policy JSON must not be empty.", nameof(json));
        }

        var document = JsonSerializer.Deserialize<PolicyDocument>(json, SerializerOptions)
            ?? throw new JsonException("Policy document was empty.");

        if (document.Version != 1)
        {
            throw new JsonException($"Unsupported PolicySharp policy version: {document.Version}.");
        }

        if (!string.Equals(document.Mode, "default-deny", StringComparison.OrdinalIgnoreCase))
        {
            throw new JsonException("PolicySharp v1 only supports mode 'default-deny'.");
        }

        return document;
    }

    private static readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions
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
    public PolicyMatch Match { get; set; } = new PolicyMatch();

    [JsonPropertyName("allow")]
    public PolicyAccess Allow { get; set; } = new PolicyAccess();

    [JsonPropertyName("deny")]
    public PolicyAccess Deny { get; set; } = new PolicyAccess();
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

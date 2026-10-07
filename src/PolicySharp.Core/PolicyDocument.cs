using System.Text.Json;
using System.Text.Json.Serialization;

namespace PolicySharp.Core;

public sealed class PolicyDocument
{
    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("rules")]
    public IReadOnlyList<PolicyRule> Rules { get; init; } = Array.Empty<PolicyRule>();

    public static PolicyDocument Parse(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        return JsonSerializer.Deserialize<PolicyDocument>(json, SerializerOptions)
            ?? throw new JsonException("Policy document was empty.");
    }

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };
}

public sealed class PolicyRule
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("kind")]
    public string Kind { get; init; } = string.Empty;

    [JsonPropertyName("symbol")]
    public string? Symbol { get; init; }

    [JsonPropertyName("from")]
    public string? From { get; init; }

    [JsonPropertyName("target")]
    public string? Target { get; init; }

    [JsonPropertyName("message")]
    public string? Message { get; init; }
}

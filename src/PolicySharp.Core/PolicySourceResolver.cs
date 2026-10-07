namespace PolicySharp.Core;

public enum PolicySourceResolutionKind
{
    Success,
    Missing,
    Ambiguous,
    Invalid
}

public sealed class PolicySourceText
{
    public PolicySourceText(string path, string? content)
    {
        Path = path ?? string.Empty;
        Content = content;
    }

    public string Path { get; }

    public string? Content { get; }
}

public sealed class PolicySourceResolution
{
    public PolicySourceResolution(
        PolicySourceResolutionKind kind,
        PolicyDocument? document,
        IReadOnlyList<string> paths,
        string? error)
    {
        Kind = kind;
        Document = document;
        Paths = paths;
        Error = error;
    }

    public PolicySourceResolutionKind Kind { get; }

    public PolicyDocument? Document { get; }

    public IReadOnlyList<string> Paths { get; }

    public string? Error { get; }

    public bool IsSuccess =>
        Kind == PolicySourceResolutionKind.Success &&
        Document is not null;
}

public static class PolicySourceResolver
{
    public static PolicySourceResolution Resolve(
        IEnumerable<PolicySourceText> sources)
    {
        if (sources is null)
        {
            throw new ArgumentNullException(nameof(sources));
        }

        var policies = sources
            .Where(source => string.Equals(
                Path.GetFileName(source.Path),
                "policysharp.json",
                StringComparison.OrdinalIgnoreCase))
            .OrderBy(source => source.Path, StringComparer.Ordinal)
            .ToArray();

        if (policies.Length == 0)
        {
            return new PolicySourceResolution(
                PolicySourceResolutionKind.Missing,
                null,
                Array.Empty<string>(),
                "policysharp.json is required.");
        }

        var paths = policies
            .Select(source => source.Path)
            .ToArray();

        if (policies.Length > 1)
        {
            return new PolicySourceResolution(
                PolicySourceResolutionKind.Ambiguous,
                null,
                paths,
                "Multiple policysharp.json files were supplied: " +
                string.Join(", ", paths));
        }

        if (string.IsNullOrWhiteSpace(policies[0].Content))
        {
            return new PolicySourceResolution(
                PolicySourceResolutionKind.Invalid,
                null,
                paths,
                "policysharp.json is empty.");
        }

        try
        {
            return new PolicySourceResolution(
                PolicySourceResolutionKind.Success,
                PolicyDocument.Parse(policies[0].Content!),
                paths,
                null);
        }
        catch (Exception exception)
        {
            return new PolicySourceResolution(
                PolicySourceResolutionKind.Invalid,
                null,
                paths,
                exception.Message);
        }
    }
}

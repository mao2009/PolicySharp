using PolicySharp.Core;
using Xunit;

namespace PolicySharp.Tests;

public sealed class PolicyDocumentTests
{
    [Fact]
    public void Parse_ReadsDefaultDenyAllowlistScope()
    {
        const string json = """
        {
          "version": 1,
          "mode": "default-deny",
          "scopes": [
            {
              "id": "domain",
              "match": {
                "namespace": "Sample.Domain.**"
              },
              "allow": {
                "namespaces": [
                  "System",
                  "Sample.Domain.**"
                ],
                "capabilities": [
                  "pure-computation"
                ]
              }
            }
          ]
        }
        """;

        var document = PolicyDocument.Parse(json);

        var scope = Assert.Single(document.Scopes);
        Assert.Equal(1, document.Version);
        Assert.Equal("default-deny", document.Mode);
        Assert.Equal("domain", scope.Id);
        Assert.Equal("Sample.Domain.**", scope.Match.Namespace);
        Assert.Contains("System", scope.Allow.Namespaces);
        Assert.Contains("pure-computation", scope.Allow.Capabilities);
    }

    [Fact]
    public void Parse_RejectsUnsupportedMode()
    {
        const string json = """
        {
          "version": 1,
          "mode": "default-allow",
          "scopes": []
        }
        """;

        Assert.Throws<System.Text.Json.JsonException>(() => PolicyDocument.Parse(json));
    }

    [Fact]
    public void Parse_RejectsUnsupportedVersion()
    {
        const string json = """
        {
          "version": 2,
          "mode": "default-deny",
          "scopes": []
        }
        """;

        Assert.Throws<System.Text.Json.JsonException>(() => PolicyDocument.Parse(json));
    }

    [Fact]
    public void Parse_RejectsDuplicateScopeIds()
    {
        const string json = """
        {
          "version": 1,
          "mode": "default-deny",
          "scopes": [
            { "id": "domain", "match": { "namespace": "A.**" } },
            { "id": "domain", "match": { "namespace": "B.**" } }
          ]
        }
        """;

        var exception = Assert.Throws<System.Text.Json.JsonException>(() => PolicyDocument.Parse(json));
        Assert.Contains("Duplicate scope id", exception.Message);
    }

    [Fact]
    public void Parse_RejectsScopeWithoutNamespaceMatch()
    {
        const string json = """
        {
          "version": 1,
          "mode": "default-deny",
          "scopes": [
            { "id": "domain", "match": {} }
          ]
        }
        """;

        Assert.Throws<System.Text.Json.JsonException>(() => PolicyDocument.Parse(json));
    }
}

using PolicySharp.Core;

namespace PolicySharp.Tests;

public sealed class PolicyDocumentTests
{
    [Fact]
    public void Parse_ReadsForbiddenApiRule()
    {
        const string json = """
        {
          "version": 1,
          "rules": [
            {
              "id": "no-process-start",
              "kind": "forbid-api",
              "symbol": "System.Diagnostics.Process.Start"
            }
          ]
        }
        """;

        var document = PolicyDocument.Parse(json);

        var rule = Assert.Single(document.Rules);
        Assert.Equal(1, document.Version);
        Assert.Equal("no-process-start", rule.Id);
        Assert.Equal("forbid-api", rule.Kind);
        Assert.Equal("System.Diagnostics.Process.Start", rule.Symbol);
    }
}

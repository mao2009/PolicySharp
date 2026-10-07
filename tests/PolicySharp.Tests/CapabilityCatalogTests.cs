using PolicySharp.Core;
using Xunit;

namespace PolicySharp.Tests;

public sealed class CapabilityCatalogTests
{
    [Fact]
    public void HttpClient_IsNetworkCapability()
    {
        var classification = CapabilityCatalog.Classify(
            "System.Net.Http",
            "System.Net.Http.HttpClient",
            "SendAsync");

        Assert.True(classification.IsSensitive);
        Assert.True(classification.IsKnown);
        Assert.Contains(PolicyCapability.Network, classification.RequiredCapabilities);
    }

    [Fact]
    public void FileReadAndWrite_AreSeparated()
    {
        var read = CapabilityCatalog.Classify("System.IO", "System.IO.File", "ReadAllText");
        var write = CapabilityCatalog.Classify("System.IO", "System.IO.File", "WriteAllText");

        Assert.Contains(PolicyCapability.FileSystemRead, read.RequiredCapabilities);
        Assert.Contains(PolicyCapability.FileSystemWrite, write.RequiredCapabilities);
    }

    [Fact]
    public void UnknownSystemIoOperation_FailsClassificationClosed()
    {
        var classification = CapabilityCatalog.Classify(
            "System.IO",
            "System.IO.File",
            "Open");

        Assert.True(classification.IsSensitive);
        Assert.False(classification.IsKnown);
    }

    [Fact]
    public void CapabilityMustBeExplicitlyAllowed()
    {
        var scope = new PolicyScope
        {
            Id = "application",
            Match = new PolicyMatch { Namespace = "Sample.Application.**" },
            Allow = new PolicyAccess
            {
                Capabilities = new[] { "Network" }
            }
        };

        Assert.True(CapabilityCatalog.IsAllowed(scope, PolicyCapability.Network));
        Assert.False(CapabilityCatalog.IsAllowed(scope, PolicyCapability.FileSystemRead));
    }

    [Fact]
    public void ExplicitCapabilityDenyWins()
    {
        var scope = new PolicyScope
        {
            Id = "application",
            Match = new PolicyMatch { Namespace = "Sample.Application.**" },
            Allow = new PolicyAccess
            {
                Capabilities = new[] { "Network" }
            },
            Deny = new PolicyAccess
            {
                Capabilities = new[] { "Network" }
            }
        };

        Assert.False(CapabilityCatalog.IsAllowed(scope, PolicyCapability.Network));
    }
}

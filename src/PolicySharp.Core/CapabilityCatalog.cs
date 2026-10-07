namespace PolicySharp.Core;

public enum PolicyCapability
{
    PureComputation,
    FileSystemRead,
    FileSystemWrite,
    Network,
    ProcessExecution,
    DatabaseRead,
    DatabaseWrite,
    Environment,
    Reflection,
    DynamicCode
}

public sealed class CapabilityClassification
{
    public CapabilityClassification(
        bool isSensitive,
        bool isKnown,
        IReadOnlyList<PolicyCapability> requiredCapabilities)
    {
        IsSensitive = isSensitive;
        IsKnown = isKnown;
        RequiredCapabilities = requiredCapabilities;
    }

    public bool IsSensitive { get; }

    public bool IsKnown { get; }

    public IReadOnlyList<PolicyCapability> RequiredCapabilities { get; }

    public static CapabilityClassification NotSensitive { get; } =
        new(false, true, Array.Empty<PolicyCapability>());

    public static CapabilityClassification UnknownSensitive { get; } =
        new(true, false, Array.Empty<PolicyCapability>());
}

public static class CapabilityCatalog
{
    public static CapabilityClassification Classify(
        string targetNamespace,
        string containingType,
        string memberName)
    {
        if (string.IsNullOrWhiteSpace(targetNamespace))
        {
            return CapabilityClassification.NotSensitive;
        }

        if (string.Equals(containingType, "System.Net.Http.HttpClient", StringComparison.Ordinal))
        {
            return Known(PolicyCapability.Network);
        }

        if (string.Equals(containingType, "System.Diagnostics.Process", StringComparison.Ordinal))
        {
            return Known(PolicyCapability.ProcessExecution);
        }

        if (string.Equals(containingType, "System.Environment", StringComparison.Ordinal))
        {
            return Known(PolicyCapability.Environment);
        }

        if (targetNamespace.StartsWith("System.Reflection.Emit", StringComparison.Ordinal))
        {
            return Known(PolicyCapability.DynamicCode);
        }

        if (targetNamespace.StartsWith("System.Reflection", StringComparison.Ordinal))
        {
            return Known(PolicyCapability.Reflection);
        }

        if (string.Equals(containingType, "System.IO.File", StringComparison.Ordinal) ||
            string.Equals(containingType, "System.IO.Directory", StringComparison.Ordinal))
        {
            return ClassifyFileSystemMember(memberName);
        }

        if (targetNamespace.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.Ordinal))
        {
            if (memberName.StartsWith("Save", StringComparison.Ordinal) ||
                memberName.StartsWith("Add", StringComparison.Ordinal) ||
                memberName.StartsWith("Update", StringComparison.Ordinal) ||
                memberName.StartsWith("Remove", StringComparison.Ordinal))
            {
                return Known(PolicyCapability.DatabaseWrite);
            }

            if (!string.IsNullOrWhiteSpace(memberName))
            {
                return Known(PolicyCapability.DatabaseRead);
            }

            return CapabilityClassification.UnknownSensitive;
        }

        if (IsSensitiveNamespace(targetNamespace))
        {
            return CapabilityClassification.UnknownSensitive;
        }

        return CapabilityClassification.NotSensitive;
    }

    public static bool IsAllowed(PolicyScope scope, PolicyCapability capability)
    {
        if (scope.Deny.Capabilities.Any(value =>
            string.Equals(value, capability.ToString(), StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        return scope.Allow.Capabilities.Any(value =>
            string.Equals(value, capability.ToString(), StringComparison.OrdinalIgnoreCase));
    }

    private static CapabilityClassification ClassifyFileSystemMember(string memberName)
    {
        if (StartsWithAny(
            memberName,
            "Read",
            "Get",
            "Enumerate",
            "Exists",
            "OpenRead"))
        {
            return Known(PolicyCapability.FileSystemRead);
        }

        if (StartsWithAny(
            memberName,
            "Write",
            "Append",
            "Create",
            "Delete",
            "Move",
            "Copy",
            "Replace",
            "Set",
            "OpenWrite"))
        {
            return Known(PolicyCapability.FileSystemWrite);
        }

        return CapabilityClassification.UnknownSensitive;
    }

    private static bool StartsWithAny(string value, params string[] prefixes) =>
        prefixes.Any(prefix => value.StartsWith(prefix, StringComparison.Ordinal));

    private static bool IsSensitiveNamespace(string targetNamespace) =>
        targetNamespace.StartsWith("System.IO", StringComparison.Ordinal) ||
        targetNamespace.StartsWith("System.Net", StringComparison.Ordinal) ||
        targetNamespace.StartsWith("System.Diagnostics", StringComparison.Ordinal) ||
        targetNamespace.StartsWith("System.Reflection", StringComparison.Ordinal) ||
        targetNamespace.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.Ordinal);

    private static CapabilityClassification Known(params PolicyCapability[] capabilities) =>
        new(true, true, capabilities);
}

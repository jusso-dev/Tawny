namespace Tawny.Domain;

public static class TenantDefaults
{
    public static readonly Guid DefaultTenantId = Guid.Parse("00000000-0000-0000-0000-000000000001");
    public const string DefaultTenantSlug = "default";
    public const string DefaultTenantName = "Default tenant";
}

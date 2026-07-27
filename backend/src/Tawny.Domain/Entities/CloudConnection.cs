namespace Tawny.Domain.Entities;

public class CloudConnection
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public required string Name { get; set; }
    public CloudProvider Provider { get; set; }
    public required string ExternalAccountId { get; set; }
    public CloudCredentialMode CredentialMode { get; set; }
    public required string ConfigurationJson { get; set; }
    public string? CredentialEncrypted { get; set; }
    public bool IsEnabled { get; set; } = true;
    public DateTimeOffset? LastTestAt { get; set; }
    public DateTimeOffset? LastSuccessAt { get; set; }
    public string? LastError { get; set; }
    public Guid? UpdatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public Tenant? Tenant { get; set; }
    public List<CloudHunt> Hunts { get; set; } = [];
}

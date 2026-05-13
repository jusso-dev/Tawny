namespace Tawny.Domain.Entities;

public class AgentRelease
{
    public required string Version { get; set; }
    public required string Platform { get; set; }
    public required string DownloadUrl { get; set; }
    public required string Sha256 { get; set; }
    public DateTimeOffset ReleasedAt { get; set; }
    public bool IsLatest { get; set; }
}

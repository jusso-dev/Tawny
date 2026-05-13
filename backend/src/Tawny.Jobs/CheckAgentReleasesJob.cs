using Microsoft.Extensions.Logging;

namespace Tawny.Jobs;

public class CheckAgentReleasesJob(ILogger<CheckAgentReleasesJob> log)
{
    public Task ExecuteAsync(CancellationToken ct = default)
    {
        log.LogInformation("CheckAgentReleasesJob: not yet implemented");
        return Task.CompletedTask;
    }
}

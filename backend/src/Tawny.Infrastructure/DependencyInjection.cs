using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Tawny.Infrastructure.Security;

namespace Tawny.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddTawnyInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("Default")
            ?? throw new InvalidOperationException("ConnectionStrings:Default is not configured.");

        services.AddDbContext<TawnyDbContext>(opt =>
            opt.UseSqlServer(connectionString, sql =>
            {
                sql.EnableRetryOnFailure(maxRetryCount: 5);
                sql.MigrationsAssembly(typeof(TawnyDbContext).Assembly.FullName);
            }));
        services.AddSingleton<IIntegrationSecretProtector, IntegrationSecretProtector>();

        return services;
    }
}

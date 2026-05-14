using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Tawny.Api.Auth;
using Tawny.Infrastructure;

namespace Tawny.Api.Tests;

public sealed class TawnyWebApplicationFactory : WebApplicationFactory<Program>
{
    public const string HmacSecret = "test-hmac-secret";
    private readonly string _databaseName = $"tawny-tests-{Guid.NewGuid()}";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Tawny:DisableHangfire"] = "true",
                ["Tawny:ApplyMigrationsOnStartup"] = "false",
                ["Tawny:WebUserHmacSecret"] = HmacSecret,
                ["Tawny:AgentJwt:RequireConfiguredSigningKey"] = "false",
            });
        });

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<TawnyDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<TawnyDbContext>>();
            services.AddDbContext<TawnyDbContext>(options => options.UseInMemoryDatabase(_databaseName));
            services.PostConfigure<WebUserAuthOptions>(TawnyAuthSchemes.WebUser, options =>
            {
                options.HmacSecret = HmacSecret;
            });

            using var provider = services.BuildServiceProvider();
            using var scope = provider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.Database.EnsureCreated();
        });
    }

    public async Task ResetDatabaseAsync()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        await db.Database.EnsureDeletedAsync();
        await db.Database.EnsureCreatedAsync();
    }

    protected override void Dispose(bool disposing) => base.Dispose(disposing);
}

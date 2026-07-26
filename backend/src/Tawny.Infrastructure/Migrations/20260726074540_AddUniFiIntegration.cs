using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tawny.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddUniFiIntegration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "UniFiIntegrations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValue: new Guid("00000000-0000-0000-0000-000000000001")),
                    BaseUrl = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    EventsUrl = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: false),
                    ApiKeyHeader = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    ApiKeyEncrypted = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RecordsPath = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    VerifyTls = table.Column<bool>(type: "bit", nullable: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    IntervalMinutes = table.Column<int>(type: "int", nullable: false),
                    NetworkVersion = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    LastTestAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    LastRunAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    LastSuccessAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    LastError = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    LastRecordsChecked = table.Column<int>(type: "int", nullable: false),
                    LastIndicatorsChecked = table.Column<int>(type: "int", nullable: false),
                    LastMatchingEvents = table.Column<int>(type: "int", nullable: false),
                    LastCasesCreated = table.Column<int>(type: "int", nullable: false),
                    UpdatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UniFiIntegrations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UniFiIntegrations_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "UniFiEventMatches",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValue: new Guid("00000000-0000-0000-0000-000000000001")),
                    UniFiIntegrationId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DedupeKey = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    EventReference = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    MatchedValuesJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    KelpieCaseId = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    KelpieCaseNumber = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UniFiEventMatches", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UniFiEventMatches_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_UniFiEventMatches_UniFiIntegrations_UniFiIntegrationId",
                        column: x => x.UniFiIntegrationId,
                        principalTable: "UniFiIntegrations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_UniFiEventMatches_TenantId_DedupeKey",
                table: "UniFiEventMatches",
                columns: new[] { "TenantId", "DedupeKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UniFiEventMatches_UniFiIntegrationId_CreatedAt",
                table: "UniFiEventMatches",
                columns: new[] { "UniFiIntegrationId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_UniFiIntegrations_IsEnabled_LastRunAt",
                table: "UniFiIntegrations",
                columns: new[] { "IsEnabled", "LastRunAt" });

            migrationBuilder.CreateIndex(
                name: "IX_UniFiIntegrations_TenantId",
                table: "UniFiIntegrations",
                column: "TenantId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UniFiEventMatches");

            migrationBuilder.DropTable(
                name: "UniFiIntegrations");
        }
    }
}

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tawny.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddCloudHunting : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CloudConnections",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValue: new Guid("00000000-0000-0000-0000-000000000001")),
                    Name = table.Column<string>(type: "nvarchar(160)", maxLength: 160, nullable: false),
                    Provider = table.Column<int>(type: "int", nullable: false),
                    ExternalAccountId = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    CredentialMode = table.Column<int>(type: "int", nullable: false),
                    Configuration = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CredentialEncrypted = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    LastTestAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    LastSuccessAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    LastError = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    UpdatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CloudConnections", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CloudConnections_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CloudHunts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValue: new Guid("00000000-0000-0000-0000-000000000001")),
                    CloudConnectionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(160)", maxLength: 160, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Source = table.Column<int>(type: "int", nullable: false),
                    Query = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    IntervalMinutes = table.Column<int>(type: "int", nullable: false),
                    LookbackMinutes = table.Column<int>(type: "int", nullable: false),
                    Severity = table.Column<int>(type: "int", nullable: false),
                    MitreTechniques = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    LastRunAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    LastSuccessAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    WatermarkAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    LastMatchCount = table.Column<int>(type: "int", nullable: false),
                    LastError = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    CreatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CloudHunts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CloudHunts_CloudConnections_CloudConnectionId",
                        column: x => x.CloudConnectionId,
                        principalTable: "CloudConnections",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_CloudHunts_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CloudFindings",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValue: new Guid("00000000-0000-0000-0000-000000000001")),
                    CloudHuntId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ProviderEventId = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    DedupeKey = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Title = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    Severity = table.Column<int>(type: "int", nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false),
                    Actor = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: true),
                    Resource = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    OccurredAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    Evidence = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CloudFindings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CloudFindings_CloudHunts_CloudHuntId",
                        column: x => x.CloudHuntId,
                        principalTable: "CloudHunts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CloudHuntRuns",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValue: new Guid("00000000-0000-0000-0000-000000000001")),
                    CloudHuntId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TriggeredByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Status = table.Column<int>(type: "int", nullable: false),
                    WindowFrom = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    WindowTo = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    StartedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    CompletedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    RecordsRead = table.Column<int>(type: "int", nullable: false),
                    FindingsCreated = table.Column<int>(type: "int", nullable: false),
                    ErrorMessage = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CloudHuntRuns", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CloudHuntRuns_CloudHunts_CloudHuntId",
                        column: x => x.CloudHuntId,
                        principalTable: "CloudHunts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CloudConnections_TenantId_IsEnabled",
                table: "CloudConnections",
                columns: new[] { "TenantId", "IsEnabled" });

            migrationBuilder.CreateIndex(
                name: "IX_CloudConnections_TenantId_Provider_Name",
                table: "CloudConnections",
                columns: new[] { "TenantId", "Provider", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CloudFindings_CloudHuntId_DedupeKey",
                table: "CloudFindings",
                columns: new[] { "CloudHuntId", "DedupeKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CloudFindings_TenantId_Status_OccurredAt",
                table: "CloudFindings",
                columns: new[] { "TenantId", "Status", "OccurredAt" },
                descending: new[] { false, false, true });

            migrationBuilder.CreateIndex(
                name: "IX_CloudHuntRuns_CloudHuntId",
                table: "CloudHuntRuns",
                column: "CloudHuntId");

            migrationBuilder.CreateIndex(
                name: "IX_CloudHuntRuns_TenantId_CloudHuntId_StartedAt",
                table: "CloudHuntRuns",
                columns: new[] { "TenantId", "CloudHuntId", "StartedAt" },
                descending: new[] { false, false, true });

            migrationBuilder.CreateIndex(
                name: "IX_CloudHunts_CloudConnectionId",
                table: "CloudHunts",
                column: "CloudConnectionId");

            migrationBuilder.CreateIndex(
                name: "IX_CloudHunts_TenantId_IsEnabled_LastRunAt",
                table: "CloudHunts",
                columns: new[] { "TenantId", "IsEnabled", "LastRunAt" });

            migrationBuilder.CreateIndex(
                name: "IX_CloudHunts_TenantId_Name",
                table: "CloudHunts",
                columns: new[] { "TenantId", "Name" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CloudFindings");

            migrationBuilder.DropTable(
                name: "CloudHuntRuns");

            migrationBuilder.DropTable(
                name: "CloudHunts");

            migrationBuilder.DropTable(
                name: "CloudConnections");
        }
    }
}

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tawny.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddTelemetryClientEventId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "ClientEventId",
                table: "TelemetryEvents",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryEvents_TenantId_AgentId_ClientEventId",
                table: "TelemetryEvents",
                columns: new[] { "TenantId", "AgentId", "ClientEventId" },
                unique: true,
                filter: "[ClientEventId] IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_TelemetryEvents_TenantId_AgentId_ClientEventId",
                table: "TelemetryEvents");

            migrationBuilder.DropColumn(
                name: "ClientEventId",
                table: "TelemetryEvents");
        }
    }
}

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tawny.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AlertsOutliveTelemetry : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Alerts_TelemetryEvents_TelemetryEventId",
                table: "Alerts");

            migrationBuilder.AddForeignKey(
                name: "FK_Alerts_TelemetryEvents_TelemetryEventId",
                table: "Alerts",
                column: "TelemetryEventId",
                principalTable: "TelemetryEvents",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Alerts_TelemetryEvents_TelemetryEventId",
                table: "Alerts");

            migrationBuilder.AddForeignKey(
                name: "FK_Alerts_TelemetryEvents_TelemetryEventId",
                table: "Alerts",
                column: "TelemetryEventId",
                principalTable: "TelemetryEvents",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}

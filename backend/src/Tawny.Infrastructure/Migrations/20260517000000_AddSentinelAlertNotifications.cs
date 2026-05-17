using System;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Tawny.Infrastructure;

#nullable disable

namespace Tawny.Infrastructure.Migrations
{
    /// <inheritdoc />
    [DbContext(typeof(TawnyDbContext))]
    [Migration("20260517000000_AddSentinelAlertNotifications")]
    public partial class AddSentinelAlertNotifications : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "SentinelNotificationError",
                table: "Alerts",
                type: "nvarchar(1024)",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "SentinelNotificationStatus",
                table: "Alerts",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "SentinelNotifiedAt",
                table: "Alerts",
                type: "datetimeoffset",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SentinelNotificationError",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "SentinelNotificationStatus",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "SentinelNotifiedAt",
                table: "Alerts");
        }
    }
}

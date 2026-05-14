using System;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Tawny.Infrastructure;

#nullable disable

namespace Tawny.Infrastructure.Migrations
{
    /// <inheritdoc />
    [DbContext(typeof(TawnyDbContext))]
    [Migration("20260514061500_AddSlackAlertNotifications")]
    public partial class AddSlackAlertNotifications : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "SlackNotificationError",
                table: "Alerts",
                type: "nvarchar(1024)",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "SlackNotificationStatus",
                table: "Alerts",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "SlackNotifiedAt",
                table: "Alerts",
                type: "datetimeoffset",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SlackNotificationError",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "SlackNotificationStatus",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "SlackNotifiedAt",
                table: "Alerts");
        }
    }
}

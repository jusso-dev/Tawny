using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tawny.Infrastructure.Migrations
{
    [DbContext(typeof(TawnyDbContext))]
    [Migration("20260726000000_AddKelpieAlertNotifications")]
    public partial class AddKelpieAlertNotifications : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "KelpieCaseId",
                table: "Alerts",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "KelpieCaseNumber",
                table: "Alerts",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "KelpieNotificationError",
                table: "Alerts",
                type: "nvarchar(1024)",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "KelpieNotificationStatus",
                table: "Alerts",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "KelpieNotifiedAt",
                table: "Alerts",
                type: "datetimeoffset",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(name: "KelpieCaseId", table: "Alerts");
            migrationBuilder.DropColumn(name: "KelpieCaseNumber", table: "Alerts");
            migrationBuilder.DropColumn(name: "KelpieNotificationError", table: "Alerts");
            migrationBuilder.DropColumn(name: "KelpieNotificationStatus", table: "Alerts");
            migrationBuilder.DropColumn(name: "KelpieNotifiedAt", table: "Alerts");
        }
    }
}

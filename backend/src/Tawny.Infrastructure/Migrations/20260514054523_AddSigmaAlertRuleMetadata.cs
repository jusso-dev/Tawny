using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tawny.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddSigmaAlertRuleMetadata : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Description",
                table: "AlertRules",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ExternalId",
                table: "AlertRules",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Format",
                table: "AlertRules",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "SourceDefinition",
                table: "AlertRules",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_AlertRules_Format_ExternalId",
                table: "AlertRules",
                columns: new[] { "Format", "ExternalId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AlertRules_Format_ExternalId",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "Description",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "ExternalId",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "Format",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "SourceDefinition",
                table: "AlertRules");
        }
    }
}

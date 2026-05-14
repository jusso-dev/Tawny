using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tawny.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddMultiTenancy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Users_Email",
                table: "Users");

            migrationBuilder.DropIndex(
                name: "IX_TelemetryEvents_AgentId_EventType_OccurredAt",
                table: "TelemetryEvents");

            migrationBuilder.DropIndex(
                name: "IX_TelemetryEvents_ReceivedAt",
                table: "TelemetryEvents");

            migrationBuilder.DropIndex(
                name: "IX_AuditLog_OccurredAt",
                table: "AuditLog");

            migrationBuilder.DropIndex(
                name: "IX_Agents_Hostname",
                table: "Agents");

            migrationBuilder.DropIndex(
                name: "IX_Agents_LastHeartbeatAt",
                table: "Agents");

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "Users",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000001"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "TelemetryEvents",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000001"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "EnrollmentTokens",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000001"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "AuditLog",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000001"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "Agents",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000001"));

            migrationBuilder.CreateTable(
                name: "Tenants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Slug = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Name = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Tenants", x => x.Id);
                });

            migrationBuilder.InsertData(
                table: "Tenants",
                columns: new[] { "Id", "CreatedAt", "Name", "Slug" },
                values: new object[] { new Guid("00000000-0000-0000-0000-000000000001"), new DateTimeOffset(new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "Default tenant", "default" });

            migrationBuilder.CreateIndex(
                name: "IX_Users_TenantId_Email",
                table: "Users",
                columns: new[] { "TenantId", "Email" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryEvents_AgentId",
                table: "TelemetryEvents",
                column: "AgentId");

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryEvents_TenantId_AgentId_EventType_OccurredAt",
                table: "TelemetryEvents",
                columns: new[] { "TenantId", "AgentId", "EventType", "OccurredAt" },
                descending: new[] { false, false, false, true });

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryEvents_TenantId_ReceivedAt",
                table: "TelemetryEvents",
                columns: new[] { "TenantId", "ReceivedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentTokens_TenantId_CreatedAt",
                table: "EnrollmentTokens",
                columns: new[] { "TenantId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLog_TenantId_OccurredAt",
                table: "AuditLog",
                columns: new[] { "TenantId", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_Agents_TenantId_Hostname",
                table: "Agents",
                columns: new[] { "TenantId", "Hostname" });

            migrationBuilder.CreateIndex(
                name: "IX_Agents_TenantId_LastHeartbeatAt",
                table: "Agents",
                columns: new[] { "TenantId", "LastHeartbeatAt" });

            migrationBuilder.CreateIndex(
                name: "IX_Tenants_Slug",
                table: "Tenants",
                column: "Slug",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_Agents_Tenants_TenantId",
                table: "Agents",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_AuditLog_Tenants_TenantId",
                table: "AuditLog",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_EnrollmentTokens_Tenants_TenantId",
                table: "EnrollmentTokens",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_TelemetryEvents_Tenants_TenantId",
                table: "TelemetryEvents",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_Users_Tenants_TenantId",
                table: "Users",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Agents_Tenants_TenantId",
                table: "Agents");

            migrationBuilder.DropForeignKey(
                name: "FK_AuditLog_Tenants_TenantId",
                table: "AuditLog");

            migrationBuilder.DropForeignKey(
                name: "FK_EnrollmentTokens_Tenants_TenantId",
                table: "EnrollmentTokens");

            migrationBuilder.DropForeignKey(
                name: "FK_TelemetryEvents_Tenants_TenantId",
                table: "TelemetryEvents");

            migrationBuilder.DropForeignKey(
                name: "FK_Users_Tenants_TenantId",
                table: "Users");

            migrationBuilder.DropTable(
                name: "Tenants");

            migrationBuilder.DropIndex(
                name: "IX_Users_TenantId_Email",
                table: "Users");

            migrationBuilder.DropIndex(
                name: "IX_TelemetryEvents_AgentId",
                table: "TelemetryEvents");

            migrationBuilder.DropIndex(
                name: "IX_TelemetryEvents_TenantId_AgentId_EventType_OccurredAt",
                table: "TelemetryEvents");

            migrationBuilder.DropIndex(
                name: "IX_TelemetryEvents_TenantId_ReceivedAt",
                table: "TelemetryEvents");

            migrationBuilder.DropIndex(
                name: "IX_EnrollmentTokens_TenantId_CreatedAt",
                table: "EnrollmentTokens");

            migrationBuilder.DropIndex(
                name: "IX_AuditLog_TenantId_OccurredAt",
                table: "AuditLog");

            migrationBuilder.DropIndex(
                name: "IX_Agents_TenantId_Hostname",
                table: "Agents");

            migrationBuilder.DropIndex(
                name: "IX_Agents_TenantId_LastHeartbeatAt",
                table: "Agents");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "TelemetryEvents");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "EnrollmentTokens");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "AuditLog");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "Agents");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryEvents_AgentId_EventType_OccurredAt",
                table: "TelemetryEvents",
                columns: new[] { "AgentId", "EventType", "OccurredAt" },
                descending: new[] { false, false, true });

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryEvents_ReceivedAt",
                table: "TelemetryEvents",
                column: "ReceivedAt");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLog_OccurredAt",
                table: "AuditLog",
                column: "OccurredAt");

            migrationBuilder.CreateIndex(
                name: "IX_Agents_Hostname",
                table: "Agents",
                column: "Hostname");

            migrationBuilder.CreateIndex(
                name: "IX_Agents_LastHeartbeatAt",
                table: "Agents",
                column: "LastHeartbeatAt");
        }
    }
}

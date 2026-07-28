using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tawny.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class SecurityHardening : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Alerts_AgentId_CreatedAt",
                table: "Alerts");

            migrationBuilder.DropIndex(
                name: "IX_Alerts_Status_CreatedAt",
                table: "Alerts");

            migrationBuilder.DropIndex(
                name: "IX_AlertRules_Format_ExternalId",
                table: "AlertRules");

            migrationBuilder.DropIndex(
                name: "IX_AlertRules_IsEnabled_EventType",
                table: "AlertRules");

            migrationBuilder.AddColumn<Guid>(
                name: "BatchId",
                table: "TelemetryEvents",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Confidence",
                table: "TelemetryEvents",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "PayloadDigest",
                table: "TelemetryEvents",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "SequenceNumber",
                table: "TelemetryEvents",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ExecutionTokenHash",
                table: "ResponseActions",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ExpiresAt",
                table: "ResponseActions",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "IdempotencyKey",
                table: "ResponseActions",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PayloadHash",
                table: "ResponseActions",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ReceivedAt",
                table: "ResponseActions",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "ResponseActions",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000001"));

            migrationBuilder.Sql("""
                UPDATE a SET a.TenantId = ag.TenantId
                FROM Alerts a
                INNER JOIN Agents ag ON ag.Id = a.AgentId;
                UPDATE ra SET ra.TenantId = ag.TenantId
                FROM ResponseActions ra
                INNER JOIN Agents ag ON ag.Id = ra.AgentId;
                """);

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "Alerts",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000001"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "AlertRules",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000001"));

            migrationBuilder.AddColumn<int>(
                name: "CredentialVersion",
                table: "Agents",
                type: "int",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<string>(
                name: "DevicePublicKey",
                table: "Agents",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "LastClockSkewSeconds",
                table: "Agents",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "LastIngestEventCount",
                table: "Agents",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<Guid>(
                name: "LastTelemetryBatchId",
                table: "Agents",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "LastTelemetrySequence",
                table: "Agents",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "RevokedAt",
                table: "Agents",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryEvents_TenantId_AgentId_BatchId",
                table: "TelemetryEvents",
                columns: new[] { "TenantId", "AgentId", "BatchId" });

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryEvents_TenantId_AgentId_SequenceNumber",
                table: "TelemetryEvents",
                columns: new[] { "TenantId", "AgentId", "SequenceNumber" });

            migrationBuilder.CreateIndex(
                name: "IX_ResponseActions_TenantId_AgentId_IdempotencyKey",
                table: "ResponseActions",
                columns: new[] { "TenantId", "AgentId", "IdempotencyKey" });

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_AgentId",
                table: "Alerts",
                column: "AgentId");

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_TenantId_AgentId_CreatedAt",
                table: "Alerts",
                columns: new[] { "TenantId", "AgentId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_TenantId_Status_CreatedAt",
                table: "Alerts",
                columns: new[] { "TenantId", "Status", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_AlertRules_TenantId_Format_ExternalId",
                table: "AlertRules",
                columns: new[] { "TenantId", "Format", "ExternalId" });

            migrationBuilder.CreateIndex(
                name: "IX_AlertRules_TenantId_IsEnabled_EventType",
                table: "AlertRules",
                columns: new[] { "TenantId", "IsEnabled", "EventType" });

            migrationBuilder.AddForeignKey(
                name: "FK_AlertRules_Tenants_TenantId",
                table: "AlertRules",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_Alerts_Tenants_TenantId",
                table: "Alerts",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AlertRules_Tenants_TenantId",
                table: "AlertRules");

            migrationBuilder.DropForeignKey(
                name: "FK_Alerts_Tenants_TenantId",
                table: "Alerts");

            migrationBuilder.DropIndex(
                name: "IX_TelemetryEvents_TenantId_AgentId_BatchId",
                table: "TelemetryEvents");

            migrationBuilder.DropIndex(
                name: "IX_TelemetryEvents_TenantId_AgentId_SequenceNumber",
                table: "TelemetryEvents");

            migrationBuilder.DropIndex(
                name: "IX_ResponseActions_TenantId_AgentId_IdempotencyKey",
                table: "ResponseActions");

            migrationBuilder.DropIndex(
                name: "IX_Alerts_AgentId",
                table: "Alerts");

            migrationBuilder.DropIndex(
                name: "IX_Alerts_TenantId_AgentId_CreatedAt",
                table: "Alerts");

            migrationBuilder.DropIndex(
                name: "IX_Alerts_TenantId_Status_CreatedAt",
                table: "Alerts");

            migrationBuilder.DropIndex(
                name: "IX_AlertRules_TenantId_Format_ExternalId",
                table: "AlertRules");

            migrationBuilder.DropIndex(
                name: "IX_AlertRules_TenantId_IsEnabled_EventType",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "BatchId",
                table: "TelemetryEvents");

            migrationBuilder.DropColumn(
                name: "Confidence",
                table: "TelemetryEvents");

            migrationBuilder.DropColumn(
                name: "PayloadDigest",
                table: "TelemetryEvents");

            migrationBuilder.DropColumn(
                name: "SequenceNumber",
                table: "TelemetryEvents");

            migrationBuilder.DropColumn(
                name: "ExecutionTokenHash",
                table: "ResponseActions");

            migrationBuilder.DropColumn(
                name: "ExpiresAt",
                table: "ResponseActions");

            migrationBuilder.DropColumn(
                name: "IdempotencyKey",
                table: "ResponseActions");

            migrationBuilder.DropColumn(
                name: "PayloadHash",
                table: "ResponseActions");

            migrationBuilder.DropColumn(
                name: "ReceivedAt",
                table: "ResponseActions");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "ResponseActions");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "AlertRules");

            migrationBuilder.DropColumn(
                name: "CredentialVersion",
                table: "Agents");

            migrationBuilder.DropColumn(
                name: "DevicePublicKey",
                table: "Agents");

            migrationBuilder.DropColumn(
                name: "LastClockSkewSeconds",
                table: "Agents");

            migrationBuilder.DropColumn(
                name: "LastIngestEventCount",
                table: "Agents");

            migrationBuilder.DropColumn(
                name: "LastTelemetryBatchId",
                table: "Agents");

            migrationBuilder.DropColumn(
                name: "LastTelemetrySequence",
                table: "Agents");

            migrationBuilder.DropColumn(
                name: "RevokedAt",
                table: "Agents");

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_AgentId_CreatedAt",
                table: "Alerts",
                columns: new[] { "AgentId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_Status_CreatedAt",
                table: "Alerts",
                columns: new[] { "Status", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_AlertRules_Format_ExternalId",
                table: "AlertRules",
                columns: new[] { "Format", "ExternalId" });

            migrationBuilder.CreateIndex(
                name: "IX_AlertRules_IsEnabled_EventType",
                table: "AlertRules",
                columns: new[] { "IsEnabled", "EventType" });
        }
    }
}

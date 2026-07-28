using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tawny.Infrastructure.Migrations;

public partial class TelemetryIntegrityAndTenantRules : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<long>(
            name: "LastTelemetrySequence",
            table: "Agents",
            type: "bigint",
            nullable: false,
            defaultValue: 0L);

        migrationBuilder.AddColumn<Guid>(
            name: "LastTelemetryBatchId",
            table: "Agents",
            type: "uniqueidentifier",
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

        migrationBuilder.AddColumn<string>(
            name: "DevicePublicKey",
            table: "Agents",
            type: "nvarchar(128)",
            maxLength: 128,
            nullable: true);

        migrationBuilder.AddColumn<Guid>(
            name: "BatchId",
            table: "TelemetryEvents",
            type: "uniqueidentifier",
            nullable: true);

        migrationBuilder.AddColumn<long>(
            name: "SequenceNumber",
            table: "TelemetryEvents",
            type: "bigint",
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

        migrationBuilder.AddColumn<Guid>(
            name: "TenantId",
            table: "AlertRules",
            type: "uniqueidentifier",
            nullable: false,
            defaultValue: new Guid("00000000-0000-0000-0000-000000000001"));

        migrationBuilder.AddColumn<Guid>(
            name: "TenantId",
            table: "Alerts",
            type: "uniqueidentifier",
            nullable: false,
            defaultValue: new Guid("00000000-0000-0000-0000-000000000001"));

        migrationBuilder.Sql("""
            UPDATE a
            SET a.TenantId = ag.TenantId
            FROM Alerts a
            INNER JOIN Agents ag ON ag.Id = a.AgentId;
            """);

        migrationBuilder.CreateIndex(
            name: "IX_TelemetryEvents_TenantId_AgentId_BatchId",
            table: "TelemetryEvents",
            columns: new[] { "TenantId", "AgentId", "BatchId" });

        migrationBuilder.CreateIndex(
            name: "IX_TelemetryEvents_TenantId_AgentId_SequenceNumber",
            table: "TelemetryEvents",
            columns: new[] { "TenantId", "AgentId", "SequenceNumber" });

        migrationBuilder.CreateIndex(
            name: "IX_AlertRules_TenantId_IsEnabled_EventType",
            table: "AlertRules",
            columns: new[] { "TenantId", "IsEnabled", "EventType" });

        migrationBuilder.CreateIndex(
            name: "IX_Alerts_TenantId_Status_CreatedAt",
            table: "Alerts",
            columns: new[] { "TenantId", "Status", "CreatedAt" });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex(name: "IX_TelemetryEvents_TenantId_AgentId_BatchId", table: "TelemetryEvents");
        migrationBuilder.DropIndex(name: "IX_TelemetryEvents_TenantId_AgentId_SequenceNumber", table: "TelemetryEvents");
        migrationBuilder.DropIndex(name: "IX_AlertRules_TenantId_IsEnabled_EventType", table: "AlertRules");
        migrationBuilder.DropIndex(name: "IX_Alerts_TenantId_Status_CreatedAt", table: "Alerts");

        migrationBuilder.DropColumn(name: "LastTelemetrySequence", table: "Agents");
        migrationBuilder.DropColumn(name: "LastTelemetryBatchId", table: "Agents");
        migrationBuilder.DropColumn(name: "LastClockSkewSeconds", table: "Agents");
        migrationBuilder.DropColumn(name: "LastIngestEventCount", table: "Agents");
        migrationBuilder.DropColumn(name: "DevicePublicKey", table: "Agents");
        migrationBuilder.DropColumn(name: "BatchId", table: "TelemetryEvents");
        migrationBuilder.DropColumn(name: "SequenceNumber", table: "TelemetryEvents");
        migrationBuilder.DropColumn(name: "Confidence", table: "TelemetryEvents");
        migrationBuilder.DropColumn(name: "PayloadDigest", table: "TelemetryEvents");
        migrationBuilder.DropColumn(name: "TenantId", table: "AlertRules");
        migrationBuilder.DropColumn(name: "TenantId", table: "Alerts");
    }
}

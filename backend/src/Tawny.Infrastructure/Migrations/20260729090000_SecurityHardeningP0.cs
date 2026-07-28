using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tawny.Infrastructure.Migrations;

/// <inheritdoc />
public partial class SecurityHardeningP0 : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<int>(
            name: "CredentialVersion",
            table: "Agents",
            type: "int",
            nullable: false,
            defaultValue: 1);

        migrationBuilder.AddColumn<DateTimeOffset>(
            name: "RevokedAt",
            table: "Agents",
            type: "datetimeoffset",
            nullable: true);

        migrationBuilder.AddColumn<Guid>(
            name: "TenantId",
            table: "ResponseActions",
            type: "uniqueidentifier",
            nullable: false,
            defaultValue: new Guid("00000000-0000-0000-0000-000000000001"));

        migrationBuilder.AddColumn<DateTimeOffset>(
            name: "ExpiresAt",
            table: "ResponseActions",
            type: "datetimeoffset",
            nullable: true);

        migrationBuilder.AddColumn<DateTimeOffset>(
            name: "ReceivedAt",
            table: "ResponseActions",
            type: "datetimeoffset",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "PayloadHash",
            table: "ResponseActions",
            type: "nvarchar(64)",
            maxLength: 64,
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "ExecutionTokenHash",
            table: "ResponseActions",
            type: "nvarchar(64)",
            maxLength: 64,
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "IdempotencyKey",
            table: "ResponseActions",
            type: "nvarchar(128)",
            maxLength: 128,
            nullable: true);

        // Backfill TenantId from Agents where possible.
        migrationBuilder.Sql("""
            UPDATE ra
            SET ra.TenantId = a.TenantId
            FROM ResponseActions ra
            INNER JOIN Agents a ON a.Id = ra.AgentId;
            """);

        migrationBuilder.CreateIndex(
            name: "IX_ResponseActions_TenantId_AgentId_IdempotencyKey",
            table: "ResponseActions",
            columns: new[] { "TenantId", "AgentId", "IdempotencyKey" });
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex(
            name: "IX_ResponseActions_TenantId_AgentId_IdempotencyKey",
            table: "ResponseActions");

        migrationBuilder.DropColumn(name: "CredentialVersion", table: "Agents");
        migrationBuilder.DropColumn(name: "RevokedAt", table: "Agents");
        migrationBuilder.DropColumn(name: "TenantId", table: "ResponseActions");
        migrationBuilder.DropColumn(name: "ExpiresAt", table: "ResponseActions");
        migrationBuilder.DropColumn(name: "ReceivedAt", table: "ResponseActions");
        migrationBuilder.DropColumn(name: "PayloadHash", table: "ResponseActions");
        migrationBuilder.DropColumn(name: "ExecutionTokenHash", table: "ResponseActions");
        migrationBuilder.DropColumn(name: "IdempotencyKey", table: "ResponseActions");
    }
}

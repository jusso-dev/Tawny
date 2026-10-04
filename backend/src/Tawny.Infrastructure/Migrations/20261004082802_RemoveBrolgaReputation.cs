using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tawny.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class RemoveBrolgaReputation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Brolga provider (3) and its AllowListed verdict (5) were removed; drop orphaned cache rows.
            migrationBuilder.Sql("DELETE FROM [ReputationCache] WHERE [Provider] = 3 OR [Verdict] = 5;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {

        }
    }
}

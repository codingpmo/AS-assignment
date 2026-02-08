using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AS_assignment.Migrations
{
    /// <inheritdoc />
    public partial class AddHasCompletedFirstPasswordChangeColumn : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "HasCompletedFirstPasswordChange",
                table: "Users",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "HasCompletedFirstPasswordChange",
                table: "Users");
        }
    }
}

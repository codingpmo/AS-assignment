using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AS_assignment.Migrations
{
    /// <inheritdoc />
    public partial class FixExistingUsersPasswordChangeFlag : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // For existing users who already have a password set, mark them as having completed first password change
            // This prevents them from getting stuck in a password change loop
            migrationBuilder.Sql(
                @"UPDATE [Users] 
                  SET [HasCompletedFirstPasswordChange] = 1 
                  WHERE [HasCompletedFirstPasswordChange] = 0 
                  AND [Id] > 0");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Revert back - set all to false
            migrationBuilder.Sql(
                @"UPDATE [Users] 
                  SET [HasCompletedFirstPasswordChange] = 0");
        }
    }
}

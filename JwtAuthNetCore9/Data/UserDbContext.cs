using JwtAuthNetCore9.Entittes;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthNetCore9.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options):DbContext(options)
    {
        public DbSet<User> Users { get; set; }
    }
}

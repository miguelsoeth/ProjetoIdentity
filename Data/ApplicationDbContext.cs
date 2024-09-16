using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ProjetoIdentity.Models;

namespace ProjetoIdentity.Data;

public class ApplicationDbContext : IdentityDbContext<IdentityUser>
{
    private readonly IConfiguration _configuration;
    
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, IConfiguration configuration)
        : base(options)
    {
        _configuration = configuration;
    }
    
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        
        var adminUsername = _configuration["DefaultAdmin:Username"];
        var adminEmail = _configuration["DefaultAdmin:Email"];
        var adminPassword = _configuration["DefaultAdmin:Password"];
        var adminRoleId = Guid.NewGuid().ToString();
        
        builder.Entity<IdentityRole>().HasData(
            UsersRoles.GetIdentityRole(UsersRoles.Admin, adminRoleId),
            UsersRoles.GetIdentityRole(UsersRoles.Gestor, Guid.NewGuid().ToString()),
            UsersRoles.GetIdentityRole(UsersRoles.Usuario, Guid.NewGuid().ToString())
        );
        
        var hasher = new PasswordHasher<IdentityUser>();
        var adminUser = new IdentityUser
        {
            Id = Guid.NewGuid().ToString(),
            UserName = adminUsername,
            NormalizedUserName = adminUsername.ToUpper(),
            Email = adminEmail,
            NormalizedEmail = adminEmail.ToUpper(),
            EmailConfirmed = true,
            PasswordHash = hasher.HashPassword(null, adminPassword), // Set a strong password here
            SecurityStamp = Guid.NewGuid().ToString()
        };
        
        builder.Entity<IdentityUser>().HasData(adminUser);
        
        builder.Entity<IdentityUserRole<string>>().HasData(new IdentityUserRole<string>
        {
            RoleId = adminRoleId,
            UserId = adminUser.Id
        });
    }
}
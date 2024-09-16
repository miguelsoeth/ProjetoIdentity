using Microsoft.AspNetCore.Identity;
using ProjetoIdentity.Util;

namespace ProjetoIdentity.Models;

public static class UsersRoles
{
    public const string Admin = "Administrador";
    public const string Gestor = "Usuário Gestor";
    public const string Usuario = "Usuário";

    public static IdentityRole GetIdentityRole(string Role, string id)
    {
        return new IdentityRole()
        {
            Id = id,
            Name = Role,
            NormalizedName = Role.ToUpper()
        };
    }
}
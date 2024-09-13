using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApiWithNpgsql.Controllers;

[ApiController]
[Route("[controller]")]
[Authorize] // Requer autenticação
public class SecureController : ControllerBase
{
    [HttpGet("message")]
    public IActionResult GetMessage()
    {
        return Ok("Você está autenticado e pode acessar esta mensagem!");
    }
    
    [HttpGet("admin")]
    [Authorize(Roles = "Admin")]
    public IActionResult GetMessageAdmin()
    {
        return Ok("Você é administrador do sistema!");
    }
    
    [HttpGet("role")]
    [Authorize]
    public IActionResult GetRole()
    {
        // Obtém as roles do usuário atual
        var roles = User.Claims
            .Where(c => c.Type == ClaimTypes.Role)
            .Select(c => c.Value);

        // Retorna as roles em uma resposta JSON
        return Ok(new { Roles = roles });
    }
}
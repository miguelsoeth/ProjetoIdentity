using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApiWithNpgsql.Controllers;

[Route("api/[controller]")]
[ApiController]
public class RoleController : ControllerBase
{
    private readonly RoleManager<IdentityRole> _roleManager;

    public RoleController(RoleManager<IdentityRole> roleManager)
    {
        _roleManager = roleManager;
    }

    [HttpPost("create")]
    public async Task<IActionResult> CreateRole(string roleName)
    {
        if (string.IsNullOrEmpty(roleName))
        {
            return BadRequest("Role name cannot be empty.");
        }

        var roleExist = await _roleManager.RoleExistsAsync(roleName);
        if (roleExist)
        {
            return BadRequest("Role already exists.");
        }

        var result = await _roleManager.CreateAsync(new IdentityRole(roleName));
        if (result.Succeeded)
        {
            return Ok("Role created successfully.");
        }

        return BadRequest(result.Errors);
    }

    [HttpGet("list")]
    public async Task<IActionResult> ListRoles()
    {
        var roles = _roleManager.Roles;
        return Ok(roles);
    }
}
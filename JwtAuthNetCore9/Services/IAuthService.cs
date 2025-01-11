using JwtAuthNetCore9.Entittes;
using JwtAuthNetCore9.Models;

namespace JwtAuthNetCore9.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDto request);
        Task<TokenResponseDto?> LoginAsync(UserDto request);
    Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto request);
    }
}

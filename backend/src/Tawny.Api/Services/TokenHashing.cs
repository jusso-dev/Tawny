using System.Security.Cryptography;
using System.Text;

namespace Tawny.Api.Services;

public static class TokenHashing
{
    public const string Prefix = "wte_";

    public static string NewToken()
    {
        Span<byte> bytes = stackalloc byte[24];
        RandomNumberGenerator.Fill(bytes);
        return Prefix + Convert.ToHexStringLower(bytes);
    }

    public static string Hash(string token)
    {
        var bytes = Encoding.UTF8.GetBytes(token);
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }
}

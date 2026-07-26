using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace Tawny.Infrastructure.Security;

public interface IIntegrationSecretProtector
{
    string Protect(string plaintext);
    string Unprotect(string protectedValue);
}

public sealed class IntegrationSecretProtector : IIntegrationSecretProtector
{
    private const string Prefix = "v1.";
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private readonly byte[] _key;

    public IntegrationSecretProtector(IConfiguration configuration)
    {
        var rootSecret = configuration["Tawny:IntegrationEncryptionKey"];
        if (string.IsNullOrWhiteSpace(rootSecret))
        {
            throw new InvalidOperationException("Tawny:IntegrationEncryptionKey is required.");
        }

        _key = HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(rootSecret),
            Encoding.UTF8.GetBytes("tawny-integration-secrets-v1"));
    }

    public string Protect(string plaintext)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(plaintext);

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        var payload = new byte[NonceSize + TagSize + ciphertext.Length];
        nonce.CopyTo(payload, 0);
        tag.CopyTo(payload, NonceSize);
        ciphertext.CopyTo(payload, NonceSize + TagSize);
        return Prefix + Convert.ToBase64String(payload);
    }

    public string Unprotect(string protectedValue)
    {
        if (!protectedValue.StartsWith(Prefix, StringComparison.Ordinal))
        {
            throw new CryptographicException("Integration secret has an unsupported format.");
        }

        var payload = Convert.FromBase64String(protectedValue[Prefix.Length..]);
        if (payload.Length <= NonceSize + TagSize)
        {
            throw new CryptographicException("Integration secret is invalid.");
        }

        var nonce = payload.AsSpan(0, NonceSize);
        var tag = payload.AsSpan(NonceSize, TagSize);
        var ciphertext = payload.AsSpan(NonceSize + TagSize);
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }
}

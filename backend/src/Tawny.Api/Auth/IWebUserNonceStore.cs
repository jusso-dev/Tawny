namespace Tawny.Api.Auth;

public interface IWebUserNonceStore
{
    /// <summary>
    /// Accept a nonce once. Returns false if the nonce was already used.
    /// </summary>
    bool TryAccept(string nonce, TimeSpan ttl);
}

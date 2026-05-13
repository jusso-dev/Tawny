using FluentAssertions;
using Tawny.Api.Services;
using Xunit;

namespace Tawny.Api.Tests;

public class TokenHashingTests
{
    [Fact]
    public void NewToken_HasPrefixAndIsRandom()
    {
        var a = TokenHashing.NewToken();
        var b = TokenHashing.NewToken();
        a.Should().StartWith(TokenHashing.Prefix);
        a.Should().NotBe(b);
    }

    [Fact]
    public void Hash_IsDeterministicAndDifferentFromInput()
    {
        var t = TokenHashing.NewToken();
        var h1 = TokenHashing.Hash(t);
        var h2 = TokenHashing.Hash(t);
        h1.Should().Be(h2);
        h1.Should().NotBe(t);
        h1.Length.Should().Be(64);
    }
}

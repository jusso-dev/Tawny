using System.Globalization;
using System.Text;
using Tawny.Domain;

namespace Tawny.Infrastructure.Hunting;

public class HuntQueryException(string message) : Exception(message);

public enum HuntOperator
{
    Equals,
    NotEquals,
    Contains,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    In,
}

public abstract record HuntNode;

public sealed record HuntAnd(HuntNode Left, HuntNode Right) : HuntNode;
public sealed record HuntOr(HuntNode Left, HuntNode Right) : HuntNode;
public sealed record HuntNot(HuntNode Inner) : HuntNode;
public sealed record HuntPredicate(string Field, HuntOperator Operator, IReadOnlyList<string> Values) : HuntNode;

public sealed record HuntQueryPlan(
    HuntNode? Filter,
    DateTimeOffset? From,
    DateTimeOffset? To,
    TelemetryEventType? EventType,
    Guid? AgentId,
    string? AgentHostnameLike,
    int Limit);

/// <summary>
/// Tiny KQL-style DSL for threat hunting across telemetry events.
/// Grammar (informal):
///   query        := orExpr
///   orExpr       := andExpr (OR andExpr)*
///   andExpr      := unaryExpr (AND unaryExpr)*
///   unaryExpr    := NOT unaryExpr | '(' orExpr ')' | predicate
///   predicate    := field op value
///   field        := identifier ('.' identifier)*
///   op           := ':' | '=' | '!=' | '>' | '<' | '>=' | '<='
///   value        := quoted-string | bareword | '[' value (',' value)* ']'
///
/// Reserved shortcut fields:
///   event_type:&lt;snake_case&gt;   -> event type filter
///   agent:&lt;hostname-substring&gt; -> agent hostname like
///   agent_id:&lt;guid&gt;           -> specific agent
///   from:&lt;iso-datetime&gt;       -> start of time window
///   to:&lt;iso-datetime&gt;         -> end of time window
///   last:&lt;duration&gt;           -> e.g. "1h", "30m", "7d"
///
/// All other fields are evaluated against the JSON payload via JSON_VALUE(Payload, '$.path').
/// </summary>
public class HuntQueryParser
{
    private const int DefaultLimit = 200;
    private const int MaxLimit = 1000;

    public HuntQueryPlan Parse(string source, int? limit = null)
    {
        var tokens = Tokenize(source);
        var pos = 0;

        DateTimeOffset? from = null;
        DateTimeOffset? to = null;
        TelemetryEventType? eventType = null;
        Guid? agentId = null;
        string? agentHostnameLike = null;

        // Extract shortcut filters first so they don't pollute the predicate tree.
        var residual = new List<Token>();
        for (var i = 0; i < tokens.Count; i++)
        {
            if (i + 2 >= tokens.Count
                || tokens[i].Kind != TokenKind.Identifier
                || tokens[i + 1].Kind != TokenKind.Colon)
            {
                residual.Add(tokens[i]);
                continue;
            }

            var field = tokens[i].Value.ToLowerInvariant();
            var valueToken = tokens[i + 2];
            if (valueToken.Kind is not (TokenKind.Identifier or TokenKind.String or TokenKind.Number))
            {
                residual.Add(tokens[i]);
                continue;
            }

            switch (field)
            {
                case "from":
                    from = ParseDateTime(valueToken.Value);
                    i += 2;
                    continue;
                case "to":
                    to = ParseDateTime(valueToken.Value);
                    i += 2;
                    continue;
                case "last":
                    var delta = ParseDuration(valueToken.Value);
                    from = DateTimeOffset.UtcNow - delta;
                    i += 2;
                    continue;
                case "event_type":
                    eventType = ParseEventType(valueToken.Value);
                    i += 2;
                    continue;
                case "agent":
                    agentHostnameLike = valueToken.Value;
                    i += 2;
                    continue;
                case "agent_id":
                    if (!Guid.TryParse(valueToken.Value, out var aid))
                    {
                        throw new HuntQueryException($"agent_id must be a GUID, got '{valueToken.Value}'.");
                    }
                    agentId = aid;
                    i += 2;
                    continue;
            }

            residual.Add(tokens[i]);
        }

        HuntNode? filter = null;
        if (residual.Count > 0)
        {
            pos = 0;
            filter = ParseOr(residual, ref pos);
            if (pos < residual.Count)
            {
                throw new HuntQueryException($"Unexpected token '{residual[pos].Value}' at position {pos}.");
            }
        }

        var resolvedLimit = Math.Clamp(limit ?? DefaultLimit, 1, MaxLimit);
        return new HuntQueryPlan(filter, from, to, eventType, agentId, agentHostnameLike, resolvedLimit);
    }

    private static HuntNode ParseOr(IReadOnlyList<Token> tokens, ref int pos)
    {
        var left = ParseAnd(tokens, ref pos);
        while (pos < tokens.Count
               && tokens[pos].Kind == TokenKind.Identifier
               && string.Equals(tokens[pos].Value, "or", StringComparison.OrdinalIgnoreCase))
        {
            pos++;
            var right = ParseAnd(tokens, ref pos);
            left = new HuntOr(left, right);
        }
        return left;
    }

    private static HuntNode ParseAnd(IReadOnlyList<Token> tokens, ref int pos)
    {
        var left = ParseUnary(tokens, ref pos);
        while (pos < tokens.Count
               && tokens[pos].Kind == TokenKind.Identifier
               && string.Equals(tokens[pos].Value, "and", StringComparison.OrdinalIgnoreCase))
        {
            pos++;
            var right = ParseUnary(tokens, ref pos);
            left = new HuntAnd(left, right);
        }
        return left;
    }

    private static HuntNode ParseUnary(IReadOnlyList<Token> tokens, ref int pos)
    {
        if (pos >= tokens.Count)
        {
            throw new HuntQueryException("Unexpected end of query.");
        }

        var token = tokens[pos];
        if (token.Kind == TokenKind.Identifier && string.Equals(token.Value, "not", StringComparison.OrdinalIgnoreCase))
        {
            pos++;
            return new HuntNot(ParseUnary(tokens, ref pos));
        }

        if (token.Kind == TokenKind.LeftParen)
        {
            pos++;
            var inner = ParseOr(tokens, ref pos);
            if (pos >= tokens.Count || tokens[pos].Kind != TokenKind.RightParen)
            {
                throw new HuntQueryException("Expected ')'.");
            }
            pos++;
            return inner;
        }

        return ParsePredicate(tokens, ref pos);
    }

    private static HuntNode ParsePredicate(IReadOnlyList<Token> tokens, ref int pos)
    {
        if (pos >= tokens.Count || tokens[pos].Kind != TokenKind.Identifier)
        {
            throw new HuntQueryException(
                pos < tokens.Count
                    ? $"Expected a field name, got '{tokens[pos].Value}'."
                    : "Expected a field name.");
        }

        var fieldBuilder = new StringBuilder(tokens[pos].Value);
        pos++;
        while (pos < tokens.Count && tokens[pos].Kind == TokenKind.Dot)
        {
            pos++;
            if (pos >= tokens.Count || tokens[pos].Kind != TokenKind.Identifier)
            {
                throw new HuntQueryException("Expected identifier after '.'.");
            }
            fieldBuilder.Append('.').Append(tokens[pos].Value);
            pos++;
        }

        if (pos >= tokens.Count)
        {
            throw new HuntQueryException($"Expected operator after field '{fieldBuilder}'.");
        }

        var op = tokens[pos].Kind switch
        {
            TokenKind.Colon or TokenKind.Equals => HuntOperator.Contains,
            TokenKind.NotEquals => HuntOperator.NotEquals,
            TokenKind.Greater => HuntOperator.GreaterThan,
            TokenKind.Less => HuntOperator.LessThan,
            TokenKind.GreaterOrEqual => HuntOperator.GreaterThanOrEqual,
            TokenKind.LessOrEqual => HuntOperator.LessThanOrEqual,
            _ => throw new HuntQueryException($"Expected operator after '{fieldBuilder}', got '{tokens[pos].Value}'.")
        };
        pos++;

        if (pos >= tokens.Count)
        {
            throw new HuntQueryException($"Expected value after operator on '{fieldBuilder}'.");
        }

        var values = new List<string>();
        if (tokens[pos].Kind == TokenKind.LeftBracket)
        {
            op = HuntOperator.In;
            pos++;
            while (pos < tokens.Count && tokens[pos].Kind != TokenKind.RightBracket)
            {
                values.Add(tokens[pos].Value);
                pos++;
                if (pos < tokens.Count && tokens[pos].Kind == TokenKind.Comma)
                {
                    pos++;
                }
            }
            if (pos >= tokens.Count)
            {
                throw new HuntQueryException("Unterminated list, expected ']'.");
            }
            pos++;
        }
        else
        {
            var raw = tokens[pos].Value;
            // `:` with a bareword that contains '*' becomes Contains-with-wildcard,
            // a quoted value with `:` becomes Equals semantics (full string match).
            if (op == HuntOperator.Contains && tokens[pos].Kind == TokenKind.String)
            {
                op = HuntOperator.Equals;
            }
            values.Add(raw.Trim('*'));
            pos++;
        }

        return new HuntPredicate(fieldBuilder.ToString(), op, values);
    }

    private static DateTimeOffset ParseDateTime(string raw)
    {
        if (!DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
        {
            throw new HuntQueryException($"Could not parse '{raw}' as an ISO-8601 datetime.");
        }
        return dt;
    }

    private static TimeSpan ParseDuration(string raw)
    {
        if (raw.Length < 2)
        {
            throw new HuntQueryException($"Could not parse duration '{raw}'. Use e.g. '15m', '2h', '7d'.");
        }
        var suffix = raw[^1];
        if (!int.TryParse(raw[..^1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var amount) || amount <= 0)
        {
            throw new HuntQueryException($"Could not parse duration '{raw}'. Use e.g. '15m', '2h', '7d'.");
        }
        return char.ToLowerInvariant(suffix) switch
        {
            's' => TimeSpan.FromSeconds(amount),
            'm' => TimeSpan.FromMinutes(amount),
            'h' => TimeSpan.FromHours(amount),
            'd' => TimeSpan.FromDays(amount),
            _ => throw new HuntQueryException($"Unknown duration suffix '{suffix}'. Use s, m, h or d."),
        };
    }

    private static TelemetryEventType ParseEventType(string raw)
    {
        return raw.ToLowerInvariant().Replace("-", "_") switch
        {
            "process_snapshot" => TelemetryEventType.ProcessSnapshot,
            "network_snapshot" => TelemetryEventType.NetworkSnapshot,
            "user_session" => TelemetryEventType.UserSession,
            "system_info" => TelemetryEventType.SystemInfo,
            "file_integrity" => TelemetryEventType.FileIntegrity,
            "heartbeat" => TelemetryEventType.Heartbeat,
            _ => throw new HuntQueryException($"Unknown event_type '{raw}'.")
        };
    }

    private enum TokenKind
    {
        Identifier,
        String,
        Number,
        Colon,
        Equals,
        NotEquals,
        Greater,
        Less,
        GreaterOrEqual,
        LessOrEqual,
        LeftParen,
        RightParen,
        LeftBracket,
        RightBracket,
        Comma,
        Dot,
    }

    private readonly record struct Token(TokenKind Kind, string Value);

    private static List<Token> Tokenize(string source)
    {
        var tokens = new List<Token>();
        var i = 0;
        while (i < source.Length)
        {
            var c = source[i];
            if (char.IsWhiteSpace(c))
            {
                i++;
                continue;
            }

            switch (c)
            {
                case '(':
                    tokens.Add(new Token(TokenKind.LeftParen, "("));
                    i++;
                    continue;
                case ')':
                    tokens.Add(new Token(TokenKind.RightParen, ")"));
                    i++;
                    continue;
                case '[':
                    tokens.Add(new Token(TokenKind.LeftBracket, "["));
                    i++;
                    continue;
                case ']':
                    tokens.Add(new Token(TokenKind.RightBracket, "]"));
                    i++;
                    continue;
                case ',':
                    tokens.Add(new Token(TokenKind.Comma, ","));
                    i++;
                    continue;
                case ':':
                    tokens.Add(new Token(TokenKind.Colon, ":"));
                    i++;
                    continue;
                case '.':
                    tokens.Add(new Token(TokenKind.Dot, "."));
                    i++;
                    continue;
                case '=':
                    tokens.Add(new Token(TokenKind.Equals, "="));
                    i++;
                    continue;
                case '!':
                    if (i + 1 < source.Length && source[i + 1] == '=')
                    {
                        tokens.Add(new Token(TokenKind.NotEquals, "!="));
                        i += 2;
                        continue;
                    }
                    throw new HuntQueryException("Expected '=' after '!'.");
                case '>':
                    if (i + 1 < source.Length && source[i + 1] == '=')
                    {
                        tokens.Add(new Token(TokenKind.GreaterOrEqual, ">="));
                        i += 2;
                    }
                    else
                    {
                        tokens.Add(new Token(TokenKind.Greater, ">"));
                        i++;
                    }
                    continue;
                case '<':
                    if (i + 1 < source.Length && source[i + 1] == '=')
                    {
                        tokens.Add(new Token(TokenKind.LessOrEqual, "<="));
                        i += 2;
                    }
                    else
                    {
                        tokens.Add(new Token(TokenKind.Less, "<"));
                        i++;
                    }
                    continue;
                case '"':
                case '\'':
                {
                    var quote = c;
                    i++;
                    var start = i;
                    while (i < source.Length && source[i] != quote)
                    {
                        if (source[i] == '\\' && i + 1 < source.Length)
                        {
                            i += 2;
                            continue;
                        }
                        i++;
                    }
                    if (i >= source.Length)
                    {
                        throw new HuntQueryException("Unterminated string literal.");
                    }
                    tokens.Add(new Token(TokenKind.String, source[start..i].Replace("\\\"", "\"").Replace("\\'", "'")));
                    i++;
                    continue;
                }
            }

            if (char.IsDigit(c) || (c == '-' && i + 1 < source.Length && char.IsDigit(source[i + 1])))
            {
                var start = i;
                if (c == '-') i++;
                while (i < source.Length && (char.IsDigit(source[i]) || source[i] == '.'))
                {
                    i++;
                }
                tokens.Add(new Token(TokenKind.Number, source[start..i]));
                continue;
            }

            if (char.IsLetter(c) || c == '_' || c == '*')
            {
                var start = i;
                while (i < source.Length && (char.IsLetterOrDigit(source[i]) || source[i] == '_' || source[i] == '-' || source[i] == '*'))
                {
                    i++;
                }
                tokens.Add(new Token(TokenKind.Identifier, source[start..i]));
                continue;
            }

            throw new HuntQueryException($"Unexpected character '{c}' at position {i}.");
        }
        return tokens;
    }
}

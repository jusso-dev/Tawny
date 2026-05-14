namespace Tawny.Domain;

public enum AgentStatus
{
    Online = 0,
    Stale = 1,
    Offline = 2,
    Unknown = 3,
}

public enum AgentPlatform
{
    Windows = 0,
    Macos = 1,
    Linux = 2,
}

public enum AgentArchitecture
{
    X64 = 0,
    Arm64 = 1,
}

public enum TelemetryEventType
{
    ProcessSnapshot = 0,
    NetworkSnapshot = 1,
    UserSession = 2,
    SystemInfo = 3,
    FileIntegrity = 4,
    Heartbeat = 5,
}

public enum UserRole
{
    Admin = 0,
    Viewer = 1,
}

public enum AlertSeverity
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

public enum AlertStatus
{
    Open = 0,
    Acknowledged = 1,
    Resolved = 2,
}

public enum AlertRuleOperator
{
    Exists = 0,
    Equals = 1,
    Contains = 2,
    GreaterThan = 3,
    LessThan = 4,
}

public enum AlertRuleFormat
{
    TawnyPredicate = 0,
    Sigma = 1,
}

public enum ResponseActionType
{
    KillProcess = 0,
    IsolateHost = 1,
}

public enum ResponseActionStatus
{
    Pending = 0,
    Dispatched = 1,
    Succeeded = 2,
    Failed = 3,
    Cancelled = 4,
}

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

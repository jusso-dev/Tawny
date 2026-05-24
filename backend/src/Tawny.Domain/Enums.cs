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
    DnsQuery = 6,
    ProcessLaunch = 7,
    FileEvent = 8,
    PackageInventory = 9,
    EditorExtension = 10,
    BrowserExtension = 11,
    McpConfig = 12,
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

public enum AlertNotificationStatus
{
    NotConfigured = 0,
    Pending = 1,
    Sent = 2,
    Failed = 3,
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
    Ioc = 2,
    Sequence = 3,
    Yara = 4,
    PackageExposure = 5,
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

public enum HuntRunStatus
{
    Running = 0,
    Succeeded = 1,
    Failed = 2,
}

public enum SuppressionScope
{
    AllRules = 0,
    SpecificRule = 1,
}

public enum ThreatIntelFeedKind
{
    UrlhausCsv = 0,
    UrlhausJson = 1,
    OtxPulse = 2,
    MispEvents = 3,
    Taxii21 = 4,
    GenericCsv = 5,
    OsvVulnerabilities = 6,
}

public enum ThreatIntelFeedStatus
{
    Healthy = 0,
    Degraded = 1,
    Failed = 2,
    NeverRun = 3,
}

public enum ReputationProvider
{
    VirusTotal = 0,
    AbuseIpDb = 1,
    GreyNoise = 2,
}

public enum ReputationVerdict
{
    Unknown = 0,
    Clean = 1,
    Suspicious = 2,
    Malicious = 3,
    Error = 4,
}

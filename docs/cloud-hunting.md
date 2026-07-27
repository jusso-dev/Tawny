# Cloud hunting and monitoring

Tawny queries cloud-native security logs and stores bounded, deduplicated
findings. It does not copy every log into Tawny, inventory cloud posture, or
replace Defender for Cloud, GuardDuty, a CSPM, or a SIEM.

Supported sources:

- AWS CloudTrail event history through `LookupEvents`.
- AWS GuardDuty findings.
- Azure Activity Logs through the `AzureActivity` table in Log Analytics.
- Microsoft Entra audit logs through `AuditLogs`.
- Microsoft Entra sign-in logs through `SigninLogs`.

Connections, credentials, hunts, run history, and findings are tenant-scoped.
The scheduler runs every minute and only executes hunts whose own interval is
due. A two-minute overlap protects against delayed provider events; provider
event IDs are hashed per hunt so overlap and manual reruns do not duplicate
findings. A failed run never advances its watermark.

## AWS setup

Create a role in the monitored account. Trust only the AWS principal used by
the Tawny host, require a unique external ID, and give the role this read-only
policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadCloudSecurityEvents",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "guardduty:GetFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

Trust-policy condition:

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<tawny-account>:role/<tawny-runtime-role>" },
  "Action": "sts:AssumeRole",
  "Condition": { "StringEquals": { "sts:ExternalId": "<unique-random-value>" } }
}
```

In **Integrations > Cloud hunting**, enter account ID, role ARN, explicit regions,
and external ID. Tawny uses its normal AWS SDK credential chain only to assume
the configured role. It does not accept long-lived customer access keys.

CloudTrail query JSON supports one native lookup attribute plus optional
client-side filters:

```json
{
  "attribute_key": "event_name",
  "attribute_value": "ConsoleLogin",
  "source_ip": "203.0.113.10",
  "error_code": "AccessDenied"
}
```

Supported attribute keys: `event_id`, `event_name`, `read_only`,
`resource_name`, `resource_type`, `username`, `access_key_id`,
and `event_source`. GuardDuty currently uses `{}` and returns findings
updated inside the hunt window.

CloudTrail event history is region-specific and limited by AWS retention and
API behavior. Add all required regions. CloudTrail Lake or S3/Athena support is
separate future work.

## Azure setup

1. Send subscription Activity Logs to a Log Analytics workspace with a
   diagnostic setting. Confirm the `AzureActivity` table contains events.
2. For identity hunts, configure Microsoft Entra diagnostic settings to send
   `AuditLogs` and `SigninLogs` to the same workspace. Availability and
   retention depend on your Entra licensing and workspace configuration.
3. Grant Tawny's managed/workload identity **Log Analytics Reader** on that
   workspace. Prefer this mode.
4. If managed identity is unavailable, create an app registration, grant the
   same workspace role, and enter tenant ID, client ID, and client secret. Tawny
   encrypts the secret at rest.
5. Enter subscription ID and Log Analytics workspace ID in Tawny, then use
   **Save and test**.

Azure hunt query JSON contains KQL. Tawny supplies the time range and appends a
hard result limit:

```json
{
  "kql": "AzureActivity | where ActivityStatusValue == 'Failure' | where OperationNameValue has 'roleAssignments' | order by TimeGenerated desc"
}
```

Entra hunt example:

```json
{
  "kql": "SigninLogs | where ResultType != 0 | where RiskLevelDuringSignIn in ('medium', 'high') | order by TimeGenerated desc"
}
```

Tawny queries these identity tables through Log Analytics. It does not request
Microsoft Graph directory permissions.

## Operational limits

- Maximum 500 matching records per hunt run.
- Evidence is capped at 64 KiB per finding.
- Initial lookback is capped at 30 days; provider retention may be shorter.
- Errors are truncated and stored without credential content.
- Deleting a connection deletes its hunts, run history, and findings.
- `TAWNY_INTEGRATION_ENCRYPTION_KEY` must be backed up with the database.

Run **Save and test** before enabling scheduled hunts. Start with 15-minute
lookback and interval, then tune filters after checking provider API volume and
finding quality.

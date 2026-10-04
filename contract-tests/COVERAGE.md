# xUnit → contract map

Source: the pre-cutover `backend/tests/Tawny.Api.Tests/*.cs` tree, except `TawnyWebApplicationFactory.cs`, `TestSecrets.cs`, and `WebUserAuthTestHelpers.cs`. That tree is deleted. This table is the record of the 92 rows.

81 xUnit methods. Theory rows are one per `InlineData`. 92 expanded rows. Contract functions in `suite.py`: 39.

A row names a function only when `suite.py` drives that behavior over HTTP. `deferred: <name>` is not a pass. Those rows have no HTTP trigger (startup validator, pure helper, sink formatter, job clock, or a second tenant). They stay deferred.

`TAWNY_CONTRACT_AUTH=session` against `tawny-server` skips the 7 HMAC signature tests. Those 7 run when `TAWNY_CONTRACT_AUTH=hmac` against the .NET API. `hmac` skips the 4 session-auth tests, which the .NET API does not serve.

| xUnit | Contract | Notes |
| --- | --- | --- |
| `AgentCredentialValidationTests.StaleCredentialVersion_IsRejectedOnEveryAgentEndpoint` | deferred: `credential_version_mismatch_rejected` | No HTTP to bump `credential_version` without also revoking. Revoke path is `test_revoked_agent_cannot_ingest`. |
| `AgentCredentialValidationTests.RoutineHeartbeatsAndIngest_DoNotWriteAuditRows` | `test_routine_ingest_skips_audit` | Audit log has no `telemetry.ingest` or `agent.heartbeat_change` for that agent. |
| `AgentCredentialValidationTests.RevokedAgent_CannotIngest` | `test_revoked_agent_cannot_ingest` | `POST /api/agents/{id}/revoke`, then events `401`. |
| `AgentFlowIntegrationTests.EnrollHeartbeatAndEventsFlow_PersistsFirstEvent` | `test_enroll_heartbeat_and_events` | Enroll `200`, heartbeat `200`, events `202`, read-back `type`. |
| `AgentFlowIntegrationTests.IngestEvents_RetryWithSameClientEventId_IsAcceptedWithoutDuplicate` | `test_client_event_id_dedupe` | Two `202`s, one stored `client_event_id`. |
| `AgentFlowIntegrationTests.WebReads_AreScopedToSignedTenant` | deferred: `web_reads_scoped_to_signed_tenant` | Needs a second tenant. No tenant-create HTTP. |
| `AgentFlowIntegrationTests.ApiTokens_ReadTenantInventory_AndAdminTokenCreatesResponseAction` | `test_api_token_inventory_and_admin_action` | Viewer `GET /api/agents` `200`, viewer action `403`, admin action `201`. Cross-tenant `404` not driven (no second tenant). |
| `AgentFlowIntegrationTests.Enroll_AcceptsLinuxAgents` | `test_linux_enroll_device_public_key` | `operating_system=linux`, `architecture=arm64`. |
| `AgentFlowIntegrationTests.IngestEvents_CreatesAlertsForMatchingRules` | `test_native_rule_creates_alert` | Alert `title`, `severity=high`, `status=open`. |
| `AgentFlowIntegrationTests.ImportedSigmaRule_CreatesAlertForMatchingTelemetry` | `test_sigma_import_creates_alert` | Import `201` `format=sigma`, matching alert title. |
| `AgentFlowIntegrationTests.ImportSigmaRule_RejectsUnsupportedModifier` | `test_sigma_rejects_modifier_re` | `400`. Body contains `Unsupported Sigma field modifier 're'`. Modifier is `re` (same exception text as the `startswith` fact). |
| `AgentFlowIntegrationTests.ImportedStixIocs_CreateRulesAndAlertForMatchingNetworkTelemetry` | `test_stix_ioc_creates_alert` | Four rules (`connections.remote_address`, `new_sha256`, `processes.command_line`, `qname`). Alert title contains `IoC IP`. |
| `AgentFlowIntegrationTests.ImportRawIocs_ReportsSkippedMd5ButImportsSha1` | `test_raw_ioc_skips_md5` | One rule `payload_path=new_sha1`, `severity=critical`. `skipped_indicators` contains `MD5`. |
| `AgentFlowIntegrationTests.ResponseActions_DispatchOnHeartbeatAndAcceptResult` | `test_response_action_dispatch_and_result` | Heartbeat returns `execution_token`. Result `204`. Replay `409` or `401`. `received_at` is not on the HTTP action DTO. |
| `AgentJwtServiceTests.IssuedToken_ValidatesWithServiceValidationKey` | deferred: `agent_jwt_round_trip` | JWT helper. No HTTP. |
| `AgentJwtServiceTests.ShouldRotate_WhenNearExpiry` | deferred: `agent_jwt_should_rotate` | Pure clock check. No HTTP. |
| `AgentRequestValidatorTests.EnrollValidator_AcceptsSupportedProductionAgent` | `test_linux_enroll_device_public_key` | linux / arm64 / `0.1.0` enroll `200`. |
| `AgentRequestValidatorTests.EnrollValidator_RejectsUnsafeOrUnsupportedIdentity` (`host\ninjected`, linux, arm64) | `test_enroll_rejects_control_hostname` | `400`, `hostname must not contain control characters.` |
| `AgentRequestValidatorTests.EnrollValidator_RejectsUnsafeOrUnsupportedIdentity` (`host`, freebsd, arm64) | `test_enroll_rejects_freebsd` | `400`, `os must be windows, macos, or linux.` |
| `AgentRequestValidatorTests.EnrollValidator_RejectsUnsafeOrUnsupportedIdentity` (`host`, linux, sparc) | `test_enroll_rejects_sparc` | `400`, `arch must be x64/amd64/x86_64 or arm64/aarch64.` |
| `AgentRequestValidatorTests.HeartbeatValidator_RejectsNegativeCounters` | `test_heartbeat_rejects_negative_counters` | `400` validation body mentions `Uptime`. |
| `AlertRuleUpdateTests.UpdatingImportedSigmaRuleMetadata_KeepsItsSourceAndFormat` | `test_sigma_metadata_update_keeps_format` | PUT `200`. `format`, `external_id`, `source_definition` unchanged. |
| `AlertRuleUpdateTests.MultiSelectionSigmaRule_CanBeDisabled` | `test_sigma_multi_selection_disable` | `match_value` null. Disable `200`. |
| `AlertRuleUpdateTests.ChangingImportedRuleMatchLogic_IsRejected` | `test_sigma_match_logic_change_rejected` | `409`, `cannot have their match logic edited`. |
| `AlertsIntegrationApiTests.ApiToken_CanPageAlertsForwardWithMitreAndAgentOs` | `test_alerts_page_after_id_mitre_agent_os` | `after_id` oldest-first, `limit`, `mitre_techniques`, `agent_os`, single GET, viewer actions `200`, viewer sigma `403`. Other-tenant alert exclusion not seeded. |
| `AlertsIntegrationApiTests.AdminApiToken_CanImportSigmaAndReadSingleAction` | `test_admin_token_sigma_and_action` | Import, disable, delete `204`, action GET. Seeded `public_ip=198.51.100.7` and `tags=["finance"]` have no HTTP writer. |
| `CrossTenantIsolationTests.AgentsAndTelemetry_AreTenantIsolated` | deferred: `cross_tenant_agents_and_telemetry` | No second tenant over HTTP. |
| `CrossTenantIsolationTests.AlertRules_AreTenantIsolated` | deferred: `cross_tenant_alert_rules` | No second tenant over HTTP. |
| `CrossTenantIsolationTests.Alerts_AreTenantIsolated` | deferred: `cross_tenant_alerts` | No second tenant over HTTP. |
| `CrossTenantIsolationTests.ResponseActions_RejectCrossTenantAgent` | deferred: `cross_tenant_response_action` | No second tenant over HTTP. |
| `CrossTenantIsolationTests.EnrollmentTokens_AreTenantIsolated` | deferred: `cross_tenant_enrollment_tokens` | No second tenant over HTTP. |
| `CrossTenantIsolationTests.ThreatIntelFeeds_AreTenantIsolated` | deferred: `cross_tenant_threat_intel_feeds` | No second tenant over HTTP. |
| `CrossTenantIsolationTests.ApiTokens_AreTenantIsolated` | deferred: `cross_tenant_api_tokens` | No second tenant over HTTP. |
| `CrossTenantIsolationTests.AuditLog_IsTenantIsolated` | deferred: `cross_tenant_audit_log` | No second tenant over HTTP. |
| `CrossTenantIsolationTests.Hunts_AreTenantIsolated` | deferred: `cross_tenant_hunts` | No second tenant over HTTP. |
| `CrossTenantIsolationTests.AgentCannotCompleteOtherAgentResponseAction` | `test_other_agent_cannot_complete_action` | Same tenant. Other agent JWT gets `404` or `401`. |
| `DeviceBatchSignatureTests.SignAndVerify_RoundTrips` | deferred: `device_batch_sign_round_trip` | Pure signature helper. |
| `DeviceBatchSignatureTests.MissingSignature_FailsVerify` | deferred: `device_batch_missing_signature` | Pure signature helper. |
| `EndpointAuthorizationInventoryTests.EveryControllerAction_DeclaresAuthorizeOrAllowAnonymous` | deferred: `endpoint_auth_inventory` | Reflection over controllers. No HTTP. |
| `MarkStaleAgentsJobTests.ExecuteAsync_TransitionsAtThreeAndFifteenMinuteBoundaries` | deferred: `mark_stale_agents_boundaries` | Job clock. No HTTP. |
| `RateLimitPartitionTests.PrincipalKeys_DifferByTenantAndUser` | deferred: `rate_limit_principal_key` | Partition key function. HTTP 429 is contract-only below. |
| `RateLimitPartitionTests.AgentEventsPartition_IncludesTenantAndAgent` | deferred: `rate_limit_agent_events_partition` | Partition key function. |
| `SecretRedactionTests.SensitiveNames_AreDetected` (`password`) | deferred: `secret_name_password` | Pure redaction. |
| `SecretRedactionTests.SensitiveNames_AreDetected` (`Authorization`) | deferred: `secret_name_authorization` | Pure redaction. |
| `SecretRedactionTests.SensitiveNames_AreDetected` (`TAWNY_WEB_HMAC_SECRET`) | deferred: `secret_name_web_hmac_secret` | Pure redaction. |
| `SecretRedactionTests.SensitiveNames_AreDetected` (`client_secret`) | deferred: `secret_name_client_secret` | Pure redaction. |
| `SecretRedactionTests.SensitiveNames_AreDetected` (`X-Signature`) | deferred: `secret_name_x_signature` | Pure redaction. |
| `SecretRedactionTests.LooksLikeSecret_DetectsJwtAndBearer` | deferred: `secret_looks_like_jwt_or_bearer` | Pure redaction. |
| `SecretRedactionTests.RedactText_ScrubsTokens` | deferred: `secret_redact_text` | Pure redaction. |
| `SentinelSinkTests.TokenProvider_RequestsClientCredentialsTokenAndCachesIt` | deferred: `sentinel_token_cache` | Outbound stub. Not the Tawny API. |
| `SentinelSinkTests.PayloadFormatter_MapsAlertToSentinelRecord` | deferred: `sentinel_payload_map` | Pure formatter. |
| `SentinelSinkTests.UploadAsync_RetriesRetryableResponses` | deferred: `sentinel_upload_retries` | Outbound stub. |
| `SentinelSinkTests.UploadAsync_DoesNotRetryNonRetryableResponses` | deferred: `sentinel_upload_no_retry` | Outbound stub. |
| `SentinelSinkTests.OptionsValidate_RequiresEndpointDcrStreamAndCredentialsWhenEnabled` | deferred: `sentinel_options_required` | Options validator. |
| `SlackAlertSinkTests.PublishAsync_SendsWebhookAndMarksAlertSent` | deferred: `slack_webhook_marks_sent` | Outbound stub. |
| `SlackAlertSinkTests.PublishAsync_MarksAlertFailedWhenWebhookRejectsRequest` | deferred: `slack_webhook_marks_failed` | Outbound stub. |
| `StarterThreatIntelFeedsTests.EnsureSeededAsync_InsertsStarterFeedsForDefaultTenant` | deferred: `starter_feeds_seed_default_tenant` | Direct DbContext seed. |
| `StarterThreatIntelFeedsTests.ThreatIntelFeedsJob_MaterialisesDomainIocAgainstDnsQuery` | deferred: `starter_feed_job_domain_ioc` | Job plus stub HTTP. |
| `TawnySocSinkTests.AlertSink_PostsBatchWithBearerToken` | deferred: `tawny_soc_bearer_batch` | Outbound stub. |
| `TawnySocSinkTests.PayloadFormatter_IncludesRelatedTelemetryById` | deferred: `tawny_soc_payload_telemetry` | Pure formatter. |
| `TawnySocSinkTests.OptionsValidate_RequiresValidEndpointWhenEnabled` | deferred: `tawny_soc_options_endpoint` | Options validator. |
| `TawnySocSinkTests.OptionsValidate_RequiresHttpsOutsideLoopbackByDefault` | deferred: `tawny_soc_options_https` | Options validator. |
| `TelemetryIntegrityTests.SequenceRollback_IsAuditedAndDoesNotAdvanceWatermark` | `test_sequence_rollback_audited` | Both batches `202`. Audit `telemetry.sequence_rollback`. `last_telemetry_sequence` is not on `AgentSummary`. |
| `TelemetryIntegrityTests.FutureTimestamp_IsRejected` | `test_future_timestamp_rejected` | `400`, `occurred_at too far in the future`. |
| `TelemetryIntegrityTests.ClientEventIdReplay_IsAcceptedWithoutDuplicate` | `test_client_event_replay_confidence` | Two `202`s, one row, `confidence=agent_reported`, `batch_id` set. |
| `TelemetryIntegrityTests.Enroll_AcceptsDevicePublicKey` | `test_linux_enroll_device_public_key` | Enroll `200` with `device_public_key`. GET agent does not return the key. |
| `TelemetryIntegrityTests.IntegrityHelpers_DetectGapAndSpike` | deferred: `telemetry_integrity_gap_and_spike` | Pure helper. |
| `TenantClaimExtensionsTests.GetTenantId_ReturnsClaimValue` | deferred: `tenant_claim_returns_value` | Claims helper. |
| `TenantClaimExtensionsTests.GetTenantId_MissingOrInvalidClaim_FailsClosed` (null) | deferred: `tenant_claim_fails_closed_null` | Claims helper. |
| `TenantClaimExtensionsTests.GetTenantId_MissingOrInvalidClaim_FailsClosed` (`""`) | deferred: `tenant_claim_fails_closed_empty` | Claims helper. |
| `TenantClaimExtensionsTests.GetTenantId_MissingOrInvalidClaim_FailsClosed` (`not-a-guid`) | deferred: `tenant_claim_fails_closed_invalid` | Claims helper. |
| `ThreatIntelFetcherTests.GenericCsv_NormalizesPublicFeedShapes` | deferred: `ti_fetch_generic_csv_shapes` | Fetcher unit. |
| `ThreatIntelFetcherTests.FetchAsync_SendsDecryptedAuthHeader` (`true`) | deferred: `ti_fetch_auth_header_encrypted` | Fetcher unit. |
| `ThreatIntelFetcherTests.FetchAsync_SendsDecryptedAuthHeader` (`false`) | deferred: `ti_fetch_auth_header_plaintext` | Fetcher unit. |
| `ThreatIntelLookupEndpointTests.Lookup_WithApiToken_ReturnsTenantFeedMatch` | deferred: `ti_lookup_feed_external_id` | Match needs `ti-feed:{id}:kind:value` on an IOC rule. Create-rule HTTP cannot set `external_id` or format. |
| `ThreatIntelLookupServiceTests.LookupAsync_ReturnsOnlyFeedBackedRulesForTenant` | deferred: `ti_lookup_service_tenant_scope` | Service unit. Same external-id gap. |
| `TokenHashingTests.NewToken_HasPrefixAndIsRandom` | deferred: `token_prefix_and_random` | Pure hash helper. |
| `TokenHashingTests.Hash_IsDeterministicAndDifferentFromInput` | deferred: `token_hash_deterministic` | Pure hash helper. |
| `WazuhSyslogFormatterTests.Format_EmitsSyslogWrappedJsonAlert` | deferred: `wazuh_syslog_json` | Pure formatter. |
| `WazuhSyslogFormatterTests.Format_OmitsTelemetryPayloadWhenMessageWouldExceedLimit` | deferred: `wazuh_syslog_size_cap` | Pure formatter. |
| `WebUserAuthHandlerTests.SignedRequest_IsAccepted` | `test_signed_request_accepted` | `GET /api/agents` `200`. |
| `WebUserAuthHandlerTests.BadSignature_IsRejected` | `test_bad_signature_rejected` | `401`. |
| `WebUserAuthHandlerTests.ReplayWindow_IsRejected` | `test_stale_timestamp_rejected` | Timestamp 5 minutes old. `401`. |
| `WebUserAuthHandlerTests.BodyTampering_InvalidatesSignature` | `test_body_tamper_rejected` | `401`. |
| `WebUserAuthHandlerTests.QueryTampering_InvalidatesSignature` | `test_query_tamper_rejected` | `401`. |
| `WebUserAuthHandlerTests.NonceReplay_IsRejected` | `test_nonce_replay_rejected` | Second use `401`. |
| `WebUserAuthHandlerTests.RoleChange_InvalidatesSignature` | `test_role_header_change_rejected` | `401`. |
| `WebUserAuthHandlerTests.WeakSecret_FailsStartupInProductionMode` | deferred: `startup_rejects_short_web_hmac_secret` | `SecurityOptionsValidator`. No HTTP. |
| `WebUserAuthHandlerTests.WeakIntegrationKey_FailsStartupInProductionMode` (null) | deferred: `startup_rejects_null_integration_key` | Startup validator. |
| `WebUserAuthHandlerTests.WeakIntegrationKey_FailsStartupInProductionMode` (`too-short`) | deferred: `startup_rejects_short_integration_key` | Startup validator. |
| `WebUserAuthHandlerTests.WeakIntegrationKey_FailsStartupInProductionMode` (`dev-only-integration-key-padding-to-32`) | deferred: `startup_rejects_dev_integration_key` | Startup validator. |
| `WebUserAuthHandlerTests.EmptySecret_FailsStartup` | deferred: `startup_rejects_empty_web_hmac_secret` | Startup validator. |

## Contract-only (no xUnit method)

| Behavior | Contract | Notes |
| --- | --- | --- |
| Anonymous health | `test_health_anonymous` | `GET /api/health` `200`, JSON `status` = `ok`. |
| Enrollment rate limit | `test_zz_agent_enrollment_rate_limit_429` | Last test. Within 11 enroll posts from this IP, a `429` body has `error`, `detail`, `policy`. `policy` is `agent-enrollment`. |
| Heartbeat rate limit | `test_agent_heartbeat_rate_limit_429` | `429` JSON. `policy` is `agent-heartbeat`. |
| Admin user CRUD | `test_admin_user_crud_default_viewer` | Session only. Default role Viewer. Duplicate email `409`. |
| Password change | `test_password_change` | Session only. `POST /api/auth/password`. |
| GitHub OAuth links existing users | `test_github_oauth_links_existing_user_only` | Session only. Unknown GitHub user is not created. |
| RS256 heartbeat rotates to EdDSA | `test_rs256_heartbeat_rotates_to_eddsa` | Session only for the enroll setup. Pre-cutover RS256 verifies. Next heartbeat returns EdDSA. |

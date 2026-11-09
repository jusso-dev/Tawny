-- Windows response (#57): new signed action types the agent can run.
ALTER TABLE response_actions DROP CONSTRAINT IF EXISTS response_actions_action_type_check;
ALTER TABLE response_actions ADD CONSTRAINT response_actions_action_type_check
    CHECK (action_type IN (
        'kill_process', 'suspend_process', 'resume_process',
        'quarantine_file', 'restore_file',
        'isolate_host', 'release_host', 'release',
        'yara_scan'
    ));

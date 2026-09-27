//! Exercise the production spawn boundary with an inert executable and isolated
//! app storage. No agent credentials, LLM, or real workspace are used.
use super::*;
use std::{os::unix::fs::PermissionsExt, time::Duration};

pub(crate) fn fixture() -> (
    tempfile::TempDir,
    tauri::App<tauri::test::MockRuntime>,
    ManagedAgentRecord,
) {
    let dir = tempfile::tempdir().unwrap();
    let app_data = dir.path().join("app-data");
    let mut context = tauri::test::mock_context(tauri::test::noop_assets());
    context.config_mut().identifier = app_data.to_str().unwrap().into();
    let state = crate::app_state::build_app_state();
    *state.relay_url_override.lock().unwrap() = Some("ws://localhost:3000".into());
    let app = tauri::test::mock_builder()
        .manage(state)
        .build(context)
        .unwrap();
    assert_eq!(app.path().app_data_dir().unwrap(), app_data);
    let probe = dir.path().join("relay-probe");
    std::fs::write(
        &probe,
        "#!/bin/sh\nprintf 'RELAY=%s\\n' \"$BUZZ_RELAY_URL\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut record = super::test_fixtures::fixture(Default::default(), vec![], None);
    record.pubkey = "ab".repeat(32);
    record.acp_command = probe.to_str().unwrap().into();
    record.agent_command = "/usr/bin/true".into();
    record.agent_command_override = Some("/usr/bin/true".into());
    // A legacy pin must never replace the invocation's workspace URL.
    record.relay_url = "wss://unrelated.example".into();
    (dir, app, record)
}

pub(crate) fn finish(process: &mut super::super::ManagedAgentProcess) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        if std::time::Instant::now() >= deadline {
            let _ = process.child.kill();
            let _ = process.child.wait();
            panic!("probe child exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn relay_target_actual_spawn_preserves_host_and_stamps_snapshot() {
    let _env = crate::managed_agents::lock_path_mutex();
    let (_dir, app, record) = fixture();
    for url in [
        "ws://localhost:3000",
        "ws://127.0.0.1:3000",
        "wss://[::1]:3443/path?community=dev",
        "wss://Relay.Example:443/path?community=dev",
    ] {
        let mut process = spawn_agent_child(app.handle(), &record, url, true, None, None).unwrap();
        finish(&mut process);
        assert_eq!(process.connect_relay_url, url);
        assert_eq!(
            process.spawn_config.relay_url,
            ManagedAgentRuntimeKey::new(&record.pubkey, url)
                .unwrap()
                .relay_url
        );
        let log = std::fs::read_to_string(&process.log_path).unwrap();
        assert_eq!(log.lines().last(), Some(format!("RELAY={url}").as_str()));
        let key = ManagedAgentRuntimeKey::new(&record.pubkey, url).unwrap();
        assert_eq!(
            process.log_path.file_stem().unwrap(),
            key.runtime_id().as_str()
        );
    }
}

#[test]
fn relay_target_workspace_start_receipt_summary_and_restart_preserve_host() {
    let _env = crate::managed_agents::lock_path_mutex();
    let (_dir, app, mut record) = fixture();
    let url = "ws://localhost:3000";
    let scoped = crate::relay::bind_expected_relay_scope(Some(url), url.into()).unwrap();
    let mut runtimes = HashMap::new();
    start_managed_agent_process(
        app.handle(),
        &mut record,
        &mut runtimes,
        None,
        &scoped,
        None,
    )
    .unwrap();
    let key = ManagedAgentRuntimeKey::new(&record.pubkey, url).unwrap();
    assert_eq!(key.relay_url, "ws://127.0.0.1:3000");
    let runtime = runtimes.get_mut(&key).unwrap();
    finish(&mut runtime.process);
    assert_eq!(runtime.connect_relay_url, url);
    assert_eq!(runtime.spawn_config.relay_url, key.relay_url);
    let receipt_path = app
        .path()
        .app_data_dir()
        .unwrap()
        .join("agents/agent-pids")
        .join(format!("{}.json", key.runtime_id()));
    let receipt: super::super::ManagedAgentRuntimeReceipt =
        serde_json::from_slice(&std::fs::read(receipt_path).unwrap()).unwrap();
    assert_eq!(receipt.key, key);
    assert_eq!(receipt.connect_relay_url.as_deref(), Some(url));

    let personas = super::super::load_personas(app.handle()).unwrap();
    let teams = super::super::load_teams(app.handle()).unwrap();
    let global = super::super::load_global_agent_config(app.handle()).unwrap();
    let summary =
        build_managed_agent_summary(app.handle(), &record, &runtimes, &personas, &teams, &global)
            .unwrap();
    assert!(
        !summary.needs_restart,
        "unexpected drift: {:?}",
        summary.restart_diff
    );
    record.parallelism += 1;
    assert!(
        build_managed_agent_summary(app.handle(), &record, &runtimes, &personas, &teams, &global,)
            .unwrap()
            .needs_restart
    );

    let urls = managed_agent_restart_targets(&runtimes, &record.pubkey);
    assert_eq!(urls, [url]);
    let mut restarted =
        spawn_agent_child(app.handle(), &record, &urls[0], false, None, None).unwrap();
    finish(&mut restarted);
    assert_eq!(restarted.connect_relay_url, url);
    assert_eq!(restarted.spawn_config.relay_url, key.relay_url);
    assert_eq!(
        std::fs::read_to_string(restarted.log_path)
            .unwrap()
            .lines()
            .last(),
        Some("RELAY=ws://localhost:3000")
    );
}

#[test]
fn relay_target_restart_selection_is_agent_scoped_and_preserves_all_connections() {
    let _env = crate::managed_agents::lock_path_mutex();
    let (_dir, app, record) = fixture();
    let mut runtimes = HashMap::new();
    for (pubkey, url) in [
        (record.pubkey.clone(), "ws://localhost:3000"),
        (
            record.pubkey.clone(),
            "wss://relay.example/path?workspace=one",
        ),
        ("cd".repeat(32), "wss://other.example"),
    ] {
        let mut other = record.clone();
        other.pubkey = pubkey.clone();
        let mut process = spawn_agent_child(app.handle(), &other, url, true, None, None).unwrap();
        finish(&mut process);
        runtimes.insert(
            ManagedAgentRuntimeKey::new(pubkey, url).unwrap(),
            ManagedAgentPairRuntime::starting(process),
        );
    }
    let mut urls = managed_agent_restart_targets(&runtimes, &record.pubkey.to_uppercase());
    urls.sort();
    assert_eq!(
        urls,
        [
            "ws://localhost:3000",
            "wss://relay.example/path?workspace=one"
        ]
    );
    assert!(managed_agent_restart_targets(&runtimes, &"ef".repeat(32)).is_empty());
    assert!(managed_agent_restart_targets(&HashMap::new(), &record.pubkey).is_empty());
}

#[test]
fn relay_target_invalid_input_refuses_before_creating_logs() {
    let _env = crate::managed_agents::lock_path_mutex();
    let (_dir, app, record) = fixture();
    for url in [
        "not a url",
        "https://localhost",
        "ws://user@localhost",
        "ws://localhost/#fragment",
    ] {
        assert!(spawn_agent_child(app.handle(), &record, url, true, None, None).is_err());
    }
    let mut invalid = record.clone();
    invalid.pubkey = "invalid".into();
    assert!(spawn_agent_child(
        app.handle(),
        &invalid,
        "ws://localhost:3000",
        true,
        None,
        None
    )
    .is_err());
    assert!(!app
        .path()
        .app_data_dir()
        .unwrap()
        .join("agents/logs")
        .exists());
    let mut process = spawn_agent_child(
        app.handle(),
        &record,
        "  ws://localhost:3000/  ",
        true,
        None,
        None,
    )
    .unwrap();
    finish(&mut process);
    assert_eq!(process.connect_relay_url, "ws://localhost:3000/");
    assert_eq!(process.spawn_config.relay_url, "ws://127.0.0.1:3000");
}

#[test]
fn relay_target_workspace_reuse_rejects_another_loopback_community() {
    let _guard = crate::managed_agents::lock_path_mutex();
    let (_dir, app, mut record) = fixture();
    // Keep the inert child alive long enough to exercise the production reuse
    // branch. exec keeps the bounded sleeper as the direct tracked child.
    std::fs::write(&record.acp_command, "#!/bin/sh\nexec /bin/sleep 5\n").unwrap();
    let configured = "ws://localhost:3000";
    let bound =
        crate::relay::bind_expected_relay_scope(Some(configured), configured.into()).unwrap();
    let mut runtimes = HashMap::new();
    start_managed_agent_process(app.handle(), &mut record, &mut runtimes, None, &bound, None)
        .unwrap();
    let other = "ws://127.0.0.1:3000";
    let bound = crate::relay::bind_expected_relay_scope(Some(other), other.into()).unwrap();
    let result =
        start_managed_agent_process(app.handle(), &mut record, &mut runtimes, None, &bound, None);
    // Clean up before asserting, including when the reuse guard regresses.
    stop_managed_agent_process(app.handle(), &mut record, &mut runtimes).unwrap();
    assert!(result.unwrap_err().contains("connection-target conflict"));
    assert!(runtimes.is_empty());
}

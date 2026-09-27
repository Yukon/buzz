//! Exercise signed inbound policy changes through the production dispatcher.
use super::*;
use crate::managed_agents::*;
use nostr::JsonUtil;

#[test]
fn relay_target_inbound_policy_restart_retains_connection_before_stop() {
    if owner_only_access_build() {
        return; // This compiled policy cannot transition away from owner-only.
    }
    let _guard = lock_path_mutex();
    let (_dir, app, mut record) = relay_target_fixture();
    let state = app.state::<AppState>();
    let owner = state.keys.lock().unwrap().clone();
    let target = "ws://localhost:3000";
    record.respond_to = RespondTo::Anyone;
    save_managed_agents(app.handle(), std::slice::from_ref(&record)).unwrap();
    let key = ManagedAgentRuntimeKey::new(&record.pubkey, target).unwrap();
    let mut process = spawn_agent_child(app.handle(), &record, target, true, None, None).unwrap();
    finish_relay_target_process(&mut process);
    state
        .managed_agent_processes
        .lock()
        .unwrap()
        .insert(key, ManagedAgentPairRuntime::starting(process));
    let mut incoming = record.clone();
    incoming.respond_to = RespondTo::OwnerOnly;
    let event = agent_events::build_agent_event(&incoming)
        .unwrap()
        .sign_with_keys(&owner)
        .unwrap();
    let refresh = reconcile_inbound_persona_event_blocking(
        event.as_json(),
        target.into(),
        app.handle().clone(),
    )
    .unwrap();
    match refresh {
        Some(InboundRuntimeRefresh::Local { pubkey, relay_urls }) => {
            assert_eq!(pubkey, record.pubkey);
            assert_eq!(relay_urls, [target]);
        }
        other => panic!("expected a local restart, got {other:?}"),
    }
    assert!(state.managed_agent_processes.lock().unwrap().is_empty());
    assert_eq!(
        load_managed_agents(app.handle()).unwrap()[0].respond_to,
        RespondTo::OwnerOnly
    );
}

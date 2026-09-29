use super::*;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn relay_target_access_probe_preserves_host_and_signed_url() {
    let _serial = crate::relay_admission::TEST_SERIAL.lock().await;
    crate::relay_admission::reset_rate_limit_gate();
    for (status, body) in [("200 OK", "[]"), ("403 Forbidden", r#"{"error":"denied"}"#)] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("ws://localhost:{port}");
        let expected_http_url = format!("http://localhost:{port}/query");
        let keys = nostr::Keys::generate();
        let mut record: super::super::ManagedAgentRecord = serde_json::from_value(serde_json::json!({
            "pubkey": keys.public_key().to_hex(), "name": "probe", "relay_url": "wss://stale.example",
            "private_key_nsec": keys.secret_key().to_secret_hex(), "acp_command": "buzz-acp",
            "agent_command": "goose", "agent_args": [], "mcp_command": "",
            "turn_timeout_seconds": 320, "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        })).unwrap();
        record.auth_tag = Some("probe-attestation".into());
        let expected_pubkey = record.pubkey.clone();
        let server = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let (end, length) = loop {
                    let mut buf = [0; 4096];
                    let count = stream.read(&mut buf).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buf[..count]);
                    assert!(request.len() < 16384);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]).to_lowercase();
                        let length: usize = headers.lines().find_map(|line|
                            line.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())
                        ).unwrap();
                        if request.len() >= end + 4 + length { break (end, length); }
                    }
                };
                let headers = String::from_utf8_lossy(&request[..end]);
                assert!(headers.starts_with("POST /query "));
                assert!(headers.to_lowercase().contains(&format!("host: localhost:{port}\r\n")));
                assert!(headers.to_lowercase().contains("x-auth-tag: probe-attestation"));
                let encoded = headers.lines().find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("authorization").then(|| value.trim().strip_prefix("Nostr ").unwrap())
                }).unwrap();
                let event: nostr::Event = serde_json::from_slice(
                    &base64::engine::general_purpose::STANDARD.decode(encoded).unwrap(),
                ).unwrap();
                event.verify().unwrap();
                assert_eq!(event.pubkey.to_hex(), expected_pubkey);
                assert!(event.tags.iter().any(|tag| tag.as_slice() == ["u", &expected_http_url]));
                let filters: serde_json::Value = serde_json::from_slice(&request[end+4..end+4+length]).unwrap();
                assert_eq!(filters[0]["kinds"], serde_json::json!([39002]));
                assert_eq!(filters[0]["#p"], serde_json::json!([expected_pubkey]));
                let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
            }).await.unwrap();
        });
        let result =
            probe_agent_relay_access(&crate::app_state::build_app_state(), record, url.clone())
                .await;
        server.await.unwrap();
        if status == "200 OK" {
            let (_, key, requested) = result.unwrap();
            assert_eq!(requested, url);
            assert_eq!(key.relay_url, format!("ws://127.0.0.1:{port}"));
        } else {
            assert!(
                result.is_err(),
                "rejected access must not become a successful probe"
            );
        }
    }
    crate::relay_admission::reset_rate_limit_gate();
}

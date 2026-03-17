use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::{AesCtr, SecureRandom};
use crate::protocol::constants::ProtoTag;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::UpstreamManager;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::duplex;
use tokio::net::TcpListener;

fn make_crypto_reader<R>(reader: R) -> CryptoReader<R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoReader::new(reader, AesCtr::new(&key, iv))
}

fn make_crypto_writer<W>(writer: W) -> CryptoWriter<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoWriter::new(writer, AesCtr::new(&key, iv), 8 * 1024)
}

#[test]
fn unknown_dc_log_is_deduplicated_per_dc_idx() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    assert!(should_log_unknown_dc(777));
    assert!(
        !should_log_unknown_dc(777),
        "same unknown dc_idx must not be logged repeatedly"
    );
    assert!(
        should_log_unknown_dc(778),
        "different unknown dc_idx must still be loggable"
    );
}

#[test]
fn unknown_dc_log_respects_distinct_limit() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    for dc in 1..=UNKNOWN_DC_LOG_DISTINCT_LIMIT {
        assert!(
            should_log_unknown_dc(dc as i16),
            "expected first-time unknown dc_idx to be loggable"
        );
    }

    assert!(
        !should_log_unknown_dc(i16::MAX),
        "distinct unknown dc_idx entries above limit must not be logged"
    );
}

#[test]
fn fallback_dc_never_panics_with_single_dc_list() {
    let mut cfg = ProxyConfig::default();
    cfg.network.prefer = 6;
    cfg.network.ipv6 = Some(true);
    cfg.default_dc = Some(42);

    let addr = get_dc_addr_static(999, &cfg).expect("fallback dc must resolve safely");
    let expected = SocketAddr::new(TG_DATACENTERS_V6[0], TG_DATACENTER_PORT);
    assert_eq!(addr, expected);
}

#[tokio::test]
async fn direct_relay_abort_midflight_releases_route_gauge() {
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let (stream, _) = tg_listener.accept().await.unwrap();
        let _hold_stream = stream;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let stats = Arc::new(Stats::new());
    let mut config = ProxyConfig::default();
    config
        .dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(config);

    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
        }],
        1,
        1,
        1,
        1,
        false,
        stats.clone(),
    ));

    let rng = Arc::new(SecureRandom::new());
    let buffer_pool = Arc::new(BufferPool::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let route_snapshot = route_runtime.snapshot();

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let client_reader = make_crypto_reader(server_reader);
    let client_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: "abort-direct-user".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: "127.0.0.1:50000".parse().unwrap(),
        is_tls: false,
    };

    let relay_task = tokio::spawn(handle_via_direct(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats.clone(),
        config,
        buffer_pool,
        rng,
        route_runtime.subscribe(),
        route_snapshot,
        0xabad1dea,
    ));

    let started = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_current_connections_direct() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(started.is_ok(), "direct relay must increment route gauge before abort");

    relay_task.abort();
    let joined = relay_task.await;
    assert!(joined.is_err(), "aborted direct relay task must return join error");

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "route gauge must be released when direct relay task is aborted mid-flight"
    );

    drop(client_side);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}

#[tokio::test]
async fn direct_relay_cutover_midflight_releases_route_gauge() {
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let (stream, _) = tg_listener.accept().await.unwrap();
        let _hold_stream = stream;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let stats = Arc::new(Stats::new());
    let mut config = ProxyConfig::default();
    config
        .dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(config);

    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
        }],
        1,
        1,
        1,
        1,
        false,
        stats.clone(),
    ));

    let rng = Arc::new(SecureRandom::new());
    let buffer_pool = Arc::new(BufferPool::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let route_snapshot = route_runtime.snapshot();

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let client_reader = make_crypto_reader(server_reader);
    let client_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: "cutover-direct-user".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: "127.0.0.1:50002".parse().unwrap(),
        is_tls: false,
    };

    let relay_task = tokio::spawn(handle_via_direct(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats.clone(),
        config,
        buffer_pool,
        rng,
        route_runtime.subscribe(),
        route_snapshot,
        0xface_cafe,
    ));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_current_connections_direct() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("direct relay must increment route gauge before cutover");

    assert!(
        route_runtime.set_mode(RelayRouteMode::Middle).is_some(),
        "cutover must advance route generation"
    );

    let relay_result = tokio::time::timeout(Duration::from_secs(6), relay_task)
        .await
        .expect("direct relay must terminate after cutover")
        .expect("direct relay task must not panic");
    assert!(
        relay_result.is_err(),
        "cutover should terminate direct relay session"
    );

    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "route gauge must be released when direct relay exits on cutover"
    );

    drop(client_side);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}

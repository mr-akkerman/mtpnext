use super::*;
use bytes::Bytes;
use crate::crypto::AesCtr;
use crate::crypto::SecureRandom;
use crate::config::{GeneralConfig, MeRouteNoWriterMode, MeSocksKdfPolicy, MeWriterPickMode};
use crate::network::probe::NetworkDecision;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter, PooledBuffer};
use crate::transport::middle_proxy::MePool;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::io::AsyncWriteExt;
use tokio::io::duplex;
use tokio::time::{Duration as TokioDuration, timeout};

fn make_pooled_payload(data: &[u8]) -> PooledBuffer {
    let pool = Arc::new(BufferPool::with_config(data.len().max(1), 4));
    let mut payload = pool.get();
    payload.resize(data.len(), 0);
    payload[..data.len()].copy_from_slice(data);
    payload
}

fn make_pooled_payload_from(pool: &Arc<BufferPool>, data: &[u8]) -> PooledBuffer {
    let mut payload = pool.get();
    payload.resize(data.len(), 0);
    payload[..data.len()].copy_from_slice(data);
    payload
}

#[test]
fn should_yield_sender_only_on_budget_with_backlog() {
    assert!(!should_yield_c2me_sender(0, true));
    assert!(!should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET - 1, true));
    assert!(!should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET, false));
    assert!(should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET, true));
}

#[tokio::test]
async fn enqueue_c2me_command_uses_try_send_fast_path() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(2);
    enqueue_c2me_command(
        &tx,
        C2MeCommand::Data {
            payload: make_pooled_payload(&[1, 2, 3]),
            flags: 0,
        },
    )
    .await
    .unwrap();

    let recv = timeout(TokioDuration::from_millis(50), rx.recv())
        .await
        .unwrap()
        .unwrap();
    match recv {
        C2MeCommand::Data { payload, flags } => {
            assert_eq!(payload.as_ref(), &[1, 2, 3]);
            assert_eq!(flags, 0);
        }
        C2MeCommand::Close => panic!("unexpected close command"),
    }
}

#[tokio::test]
async fn enqueue_c2me_command_falls_back_to_send_when_queue_is_full() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(1);
    tx.send(C2MeCommand::Data {
        payload: make_pooled_payload(&[9]),
        flags: 9,
    })
    .await
    .unwrap();

    let tx2 = tx.clone();
    let producer = tokio::spawn(async move {
        enqueue_c2me_command(
            &tx2,
            C2MeCommand::Data {
                payload: make_pooled_payload(&[7, 7]),
                flags: 7,
            },
        )
        .await
        .unwrap();
    });

    let _ = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap();
    producer.await.unwrap();

    let recv = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .unwrap();
    match recv {
        C2MeCommand::Data { payload, flags } => {
            assert_eq!(payload.as_ref(), &[7, 7]);
            assert_eq!(flags, 7);
        }
        C2MeCommand::Close => panic!("unexpected close command"),
    }
}

#[tokio::test]
async fn enqueue_c2me_command_closed_channel_recycles_payload() {
    let pool = Arc::new(BufferPool::with_config(64, 4));
    let payload = make_pooled_payload_from(&pool, &[1, 2, 3, 4]);
    let (tx, rx) = mpsc::channel::<C2MeCommand>(1);
    drop(rx);

    let result = enqueue_c2me_command(
        &tx,
        C2MeCommand::Data {
            payload,
            flags: 0,
        },
    )
    .await;

    assert!(result.is_err(), "closed queue must fail enqueue");
    drop(result);
    assert!(
        pool.stats().pooled >= 1,
        "payload must return to pool when enqueue fails on closed channel"
    );
}

#[tokio::test]
async fn enqueue_c2me_command_full_then_closed_recycles_waiting_payload() {
    let pool = Arc::new(BufferPool::with_config(64, 4));
    let (tx, rx) = mpsc::channel::<C2MeCommand>(1);

    tx.send(C2MeCommand::Data {
        payload: make_pooled_payload_from(&pool, &[9]),
        flags: 1,
    })
    .await
    .unwrap();

    let tx2 = tx.clone();
    let pool2 = pool.clone();
    let blocked_send = tokio::spawn(async move {
        enqueue_c2me_command(
            &tx2,
            C2MeCommand::Data {
                payload: make_pooled_payload_from(&pool2, &[7, 7, 7]),
                flags: 2,
            },
        )
        .await
    });

    tokio::time::sleep(TokioDuration::from_millis(10)).await;
    drop(rx);

    let result = timeout(TokioDuration::from_secs(1), blocked_send)
        .await
        .expect("blocked send task must finish")
        .expect("blocked send task must not panic");

    assert!(
        result.is_err(),
        "closing receiver while sender is blocked must fail enqueue"
    );
    drop(result);
    assert!(
        pool.stats().pooled >= 2,
        "both queued and blocked payloads must return to pool after channel close"
    );
}

#[test]
fn desync_dedup_cache_is_bounded() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let now = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        assert!(
            should_emit_full_desync(key, false, now),
            "unique keys up to cap must be tracked"
        );
    }

    assert!(
        !should_emit_full_desync(u64::MAX, false, now),
        "new key above cap must remain suppressed to avoid log amplification"
    );

    assert!(
        !should_emit_full_desync(7, false, now),
        "already tracked key inside dedup window must stay suppressed"
    );
}

#[test]
fn desync_dedup_full_cache_churn_stays_suppressed() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let now = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        assert!(should_emit_full_desync(key, false, now));
    }

    for offset in 0..2048u64 {
        assert!(
            !should_emit_full_desync(u64::MAX - offset, false, now),
            "fresh full-cache churn must remain suppressed under pressure"
        );
    }
}

fn make_forensics_state() -> RelayForensicsState {
    RelayForensicsState {
        trace_id: 1,
        conn_id: 2,
        user: "test-user".to_string(),
        peer: "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
        peer_hash: 3,
        started_at: Instant::now(),
        bytes_c2me: 0,
        bytes_me2c: Arc::new(AtomicU64::new(0)),
        desync_all_full: false,
    }
}

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

async fn make_me_pool_for_abort_test(stats: Arc<Stats>) -> Arc<MePool> {
    let general = GeneralConfig::default();

    MePool::new(
        None,
        vec![1u8; 32],
        None,
        false,
        None,
        Vec::new(),
        1,
        None,
        12,
        1200,
        HashMap::new(),
        HashMap::new(),
        None,
        NetworkDecision::default(),
        None,
        Arc::new(SecureRandom::new()),
        stats,
        general.me_keepalive_enabled,
        general.me_keepalive_interval_secs,
        general.me_keepalive_jitter_secs,
        general.me_keepalive_payload_random,
        general.rpc_proxy_req_every,
        general.me_warmup_stagger_enabled,
        general.me_warmup_step_delay_ms,
        general.me_warmup_step_jitter_ms,
        general.me_reconnect_max_concurrent_per_dc,
        general.me_reconnect_backoff_base_ms,
        general.me_reconnect_backoff_cap_ms,
        general.me_reconnect_fast_retry_count,
        general.me_single_endpoint_shadow_writers,
        general.me_single_endpoint_outage_mode_enabled,
        general.me_single_endpoint_outage_disable_quarantine,
        general.me_single_endpoint_outage_backoff_min_ms,
        general.me_single_endpoint_outage_backoff_max_ms,
        general.me_single_endpoint_shadow_rotate_every_secs,
        general.me_floor_mode,
        general.me_adaptive_floor_idle_secs,
        general.me_adaptive_floor_min_writers_single_endpoint,
        general.me_adaptive_floor_min_writers_multi_endpoint,
        general.me_adaptive_floor_recover_grace_secs,
        general.me_adaptive_floor_writers_per_core_total,
        general.me_adaptive_floor_cpu_cores_override,
        general.me_adaptive_floor_max_extra_writers_single_per_core,
        general.me_adaptive_floor_max_extra_writers_multi_per_core,
        general.me_adaptive_floor_max_active_writers_per_core,
        general.me_adaptive_floor_max_warm_writers_per_core,
        general.me_adaptive_floor_max_active_writers_global,
        general.me_adaptive_floor_max_warm_writers_global,
        general.hardswap,
        general.me_pool_drain_ttl_secs,
        general.me_pool_drain_threshold,
        general.effective_me_pool_force_close_secs(),
        general.me_pool_min_fresh_ratio,
        general.me_hardswap_warmup_delay_min_ms,
        general.me_hardswap_warmup_delay_max_ms,
        general.me_hardswap_warmup_extra_passes,
        general.me_hardswap_warmup_pass_backoff_base_ms,
        general.me_bind_stale_mode,
        general.me_bind_stale_ttl_secs,
        general.me_secret_atomic_snapshot,
        general.me_deterministic_writer_sort,
        MeWriterPickMode::default(),
        general.me_writer_pick_sample_size,
        MeSocksKdfPolicy::default(),
        general.me_writer_cmd_channel_capacity,
        general.me_route_channel_capacity,
        general.me_route_backpressure_base_timeout_ms,
        general.me_route_backpressure_high_timeout_ms,
        general.me_route_backpressure_high_watermark_pct,
        general.me_reader_route_data_wait_ms,
        general.me_health_interval_ms_unhealthy,
        general.me_health_interval_ms_healthy,
        general.me_warn_rate_limit_ms,
        MeRouteNoWriterMode::default(),
        general.me_route_no_writer_wait_ms,
        general.me_route_inline_recovery_attempts,
        general.me_route_inline_recovery_wait_ms,
    )
}

fn encrypt_for_reader(plaintext: &[u8]) -> Vec<u8> {
    let key = [0u8; 32];
    let iv = 0u128;
    let mut cipher = AesCtr::new(&key, iv);
    cipher.encrypt(plaintext)
}

#[tokio::test]
async fn read_client_payload_times_out_on_header_stall() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");
    let (reader, _writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_millis(25),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "stalled header read must time out"
    );
}

#[tokio::test]
async fn read_client_payload_times_out_on_payload_stall() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");
    let (reader, mut writer) = duplex(1024);
    let encrypted_len = encrypt_for_reader(&[8, 0, 0, 0]);
    writer.write_all(&encrypted_len).await.unwrap();

    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_millis(25),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "stalled payload body read must time out"
    );
}

#[tokio::test]
async fn read_client_payload_large_intermediate_frame_is_exact() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(262_144);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload_len = buffer_pool.buffer_size().saturating_mul(3).max(65_537);
    let mut plaintext = Vec::with_capacity(4 + payload_len);
    plaintext.extend_from_slice(&(payload_len as u32).to_le_bytes());
    plaintext.extend((0..payload_len).map(|idx| (idx as u8).wrapping_mul(31)));

    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let read = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        payload_len + 16,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("payload read must succeed")
    .expect("frame must be present");

    let (frame, quickack) = read;
    assert!(!quickack, "quickack flag must be unset");
    assert_eq!(frame.len(), payload_len, "payload size must match wire length");
    for (idx, byte) in frame.iter().enumerate() {
        assert_eq!(*byte, (idx as u8).wrapping_mul(31));
    }
    assert_eq!(frame_counter, 1, "exactly one frame must be counted");
}

#[tokio::test]
async fn read_client_payload_secure_strips_tail_padding_bytes() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload = [0x11u8, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd];
    let tail = [0xeeu8, 0xff, 0x99];
    let wire_len = payload.len() + tail.len();

    let mut plaintext = Vec::with_capacity(4 + wire_len);
    plaintext.extend_from_slice(&(wire_len as u32).to_le_bytes());
    plaintext.extend_from_slice(&payload);
    plaintext.extend_from_slice(&tail);
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let read = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Secure,
        1024,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("secure payload read must succeed")
    .expect("secure frame must be present");

    let (frame, quickack) = read;
    assert!(!quickack, "quickack flag must be unset");
    assert_eq!(frame.as_ref(), &payload);
    assert_eq!(frame_counter, 1, "one secure frame must be counted");
}

#[tokio::test]
async fn read_client_payload_secure_rejects_wire_len_below_4() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let mut plaintext = Vec::with_capacity(7);
    plaintext.extend_from_slice(&3u32.to_le_bytes());
    plaintext.extend_from_slice(&[1u8, 2, 3]);
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Secure,
        1024,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Proxy(ref msg)) if msg.contains("Frame too small: 3")),
        "secure wire length below 4 must be fail-closed by the frame-too-small guard"
    );
}

#[tokio::test]
async fn read_client_payload_intermediate_skips_zero_len_frame() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload = [7u8, 6, 5, 4, 3, 2, 1, 0];
    let mut plaintext = Vec::with_capacity(4 + 4 + payload.len());
    plaintext.extend_from_slice(&0u32.to_le_bytes());
    plaintext.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(&payload);
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let read = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("intermediate payload read must succeed")
    .expect("frame must be present");

    let (frame, quickack) = read;
    assert!(!quickack, "quickack flag must be unset");
    assert_eq!(frame.as_ref(), &payload);
    assert_eq!(frame_counter, 1, "zero-length frame must be skipped");
}

#[tokio::test]
async fn read_client_payload_abridged_extended_len_sets_quickack() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload_len = 4 * 130;
    let len_words = (payload_len / 4) as u32;
    let mut plaintext = Vec::with_capacity(1 + 3 + payload_len);
    plaintext.push(0xff | 0x80);
    let lw = len_words.to_le_bytes();
    plaintext.extend_from_slice(&lw[..3]);
    plaintext.extend((0..payload_len).map(|idx| (idx as u8).wrapping_add(17)));

    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let read = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Abridged,
        payload_len + 16,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("abridged payload read must succeed")
    .expect("frame must be present");

    let (frame, quickack) = read;
    assert!(quickack, "quickack bit must be propagated from abridged header");
    assert_eq!(frame.len(), payload_len);
    assert_eq!(frame_counter, 1, "one abridged frame must be counted");
}

#[tokio::test]
async fn read_client_payload_returns_buffer_to_pool_after_emit() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let pool = Arc::new(BufferPool::with_config(64, 8));
    pool.preallocate(1);
    assert_eq!(pool.stats().pooled, 1, "precondition: one pooled buffer");

    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    // Force growth beyond default pool buffer size to catch ownership-take regressions.
    let payload_len = 257usize;
    let mut plaintext = Vec::with_capacity(4 + payload_len);
    plaintext.extend_from_slice(&(payload_len as u32).to_le_bytes());
    plaintext.extend((0..payload_len).map(|idx| (idx as u8).wrapping_mul(13)));

    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let _ = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        payload_len + 8,
        TokioDuration::from_secs(1),
        &pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("payload read must succeed")
    .expect("frame must be present");

    assert_eq!(frame_counter, 1);
    let pool_stats = pool.stats();
    assert!(
        pool_stats.pooled >= 1,
        "emitted payload buffer must be returned to pool to avoid pool drain"
    );
}

#[tokio::test]
async fn read_client_payload_keeps_pool_buffer_checked_out_until_frame_drop() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let pool = Arc::new(BufferPool::with_config(64, 2));
    pool.preallocate(1);
    assert_eq!(pool.stats().pooled, 1, "one pooled buffer must be available");

    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload = [0x41u8, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48];
    let mut plaintext = Vec::with_capacity(4 + payload.len());
    plaintext.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(&payload);
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let (frame, quickack) = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_secs(1),
        &pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("payload read must succeed")
    .expect("frame must be present");

    assert!(!quickack);
    assert_eq!(frame.as_ref(), &payload);
    assert_eq!(
        pool.stats().pooled,
        0,
        "buffer must stay checked out while frame payload is alive"
    );

    drop(frame);
    assert!(
        pool.stats().pooled >= 1,
        "buffer must return to pool only after frame drop"
    );
}

#[tokio::test]
async fn enqueue_c2me_close_unblocks_after_queue_drain() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(1);
    tx.send(C2MeCommand::Data {
        payload: make_pooled_payload(&[0x41]),
        flags: 0,
    })
    .await
    .unwrap();

    let tx2 = tx.clone();
    let close_task = tokio::spawn(async move { enqueue_c2me_command(&tx2, C2MeCommand::Close).await });

    tokio::time::sleep(TokioDuration::from_millis(10)).await;

    let first = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .expect("first queued item must be present");
    assert!(matches!(first, C2MeCommand::Data { .. }));

    close_task.await.unwrap().expect("close enqueue must succeed after drain");

    let second = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .expect("close command must follow after queue drain");
    assert!(matches!(second, C2MeCommand::Close));
}

#[tokio::test]
async fn enqueue_c2me_close_full_then_receiver_drop_fails_cleanly() {
    let (tx, rx) = mpsc::channel::<C2MeCommand>(1);
    tx.send(C2MeCommand::Data {
        payload: make_pooled_payload(&[0x42]),
        flags: 0,
    })
    .await
    .unwrap();

    let tx2 = tx.clone();
    let close_task = tokio::spawn(async move { enqueue_c2me_command(&tx2, C2MeCommand::Close).await });

    tokio::time::sleep(TokioDuration::from_millis(10)).await;
    drop(rx);

    let result = timeout(TokioDuration::from_secs(1), close_task)
        .await
        .expect("close task must finish")
        .expect("close task must not panic");
    assert!(
        result.is_err(),
        "close enqueue must fail cleanly when receiver is dropped under pressure"
    );
}

#[tokio::test]
async fn process_me_writer_response_ack_obeys_flush_policy() {
    let (writer_side, _reader_side) = duplex(1024);
    let mut writer = make_crypto_writer(writer_side);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let stats = Stats::new();
    let bytes_me2c = AtomicU64::new(0);

    let immediate = process_me_writer_response(
        MeResponse::Ack(0x11223344),
        &mut writer,
        ProtoTag::Intermediate,
        &rng,
        &mut frame_buf,
        &stats,
        "user",
        &bytes_me2c,
        77,
        true,
        false,
    )
    .await
    .expect("ack response must be processed");

    assert!(matches!(
        immediate,
        MeWriterResponseOutcome::Continue {
            frames: 1,
            bytes: 4,
            flush_immediately: true,
        }
    ));

    let delayed = process_me_writer_response(
        MeResponse::Ack(0x55667788),
        &mut writer,
        ProtoTag::Intermediate,
        &rng,
        &mut frame_buf,
        &stats,
        "user",
        &bytes_me2c,
        77,
        false,
        false,
    )
    .await
    .expect("ack response must be processed");

    assert!(matches!(
        delayed,
        MeWriterResponseOutcome::Continue {
            frames: 1,
            bytes: 4,
            flush_immediately: false,
        }
    ));
}

#[tokio::test]
async fn process_me_writer_response_data_updates_byte_accounting() {
    let (writer_side, _reader_side) = duplex(1024);
    let mut writer = make_crypto_writer(writer_side);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let stats = Stats::new();
    let bytes_me2c = AtomicU64::new(0);

    let payload = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9];
    let outcome = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from(payload.clone()),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &rng,
        &mut frame_buf,
        &stats,
        "user",
        &bytes_me2c,
        88,
        false,
        false,
    )
    .await
    .expect("data response must be processed");

    assert!(matches!(
        outcome,
        MeWriterResponseOutcome::Continue {
            frames: 1,
            bytes,
            flush_immediately: false,
        } if bytes == payload.len()
    ));
    assert_eq!(
        bytes_me2c.load(std::sync::atomic::Ordering::Relaxed),
        payload.len() as u64,
        "ME->C byte accounting must increase by emitted payload size"
    );
}

#[tokio::test]
async fn middle_relay_abort_midflight_releases_route_gauge() {
    let stats = Arc::new(Stats::new());
    let me_pool = make_me_pool_for_abort_test(stats.clone()).await;
    let config = Arc::new(ProxyConfig::default());
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());

    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Middle));
    let route_snapshot = route_runtime.snapshot();

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let crypto_reader = make_crypto_reader(server_reader);
    let crypto_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: "abort-middle-user".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: "127.0.0.1:50001".parse().unwrap(),
        is_tls: false,
    };

    let relay_task = tokio::spawn(handle_via_middle_proxy(
        crypto_reader,
        crypto_writer,
        success,
        me_pool,
        stats.clone(),
        config,
        buffer_pool,
        "127.0.0.1:443".parse().unwrap(),
        rng,
        route_runtime.subscribe(),
        route_snapshot,
        0xdecafbad,
    ));

    let started = tokio::time::timeout(TokioDuration::from_secs(2), async {
        loop {
            if stats.get_current_connections_me() == 1 {
                break;
            }
            tokio::time::sleep(TokioDuration::from_millis(10)).await;
        }
    })
    .await;
    assert!(started.is_ok(), "middle relay must increment route gauge before abort");

    relay_task.abort();
    let joined = relay_task.await;
    assert!(joined.is_err(), "aborted middle relay task must return join error");

    tokio::time::sleep(TokioDuration::from_millis(20)).await;
    assert_eq!(
        stats.get_current_connections_me(),
        0,
        "route gauge must be released when middle relay task is aborted mid-flight"
    );

    drop(client_side);
}

#[tokio::test]
async fn middle_relay_cutover_midflight_releases_route_gauge() {
    let stats = Arc::new(Stats::new());
    let me_pool = make_me_pool_for_abort_test(stats.clone()).await;
    let config = Arc::new(ProxyConfig::default());
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());

    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Middle));
    let route_snapshot = route_runtime.snapshot();

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let crypto_reader = make_crypto_reader(server_reader);
    let crypto_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: "cutover-middle-user".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: "127.0.0.1:50003".parse().unwrap(),
        is_tls: false,
    };

    let relay_task = tokio::spawn(handle_via_middle_proxy(
        crypto_reader,
        crypto_writer,
        success,
        me_pool,
        stats.clone(),
        config,
        buffer_pool,
        "127.0.0.1:443".parse().unwrap(),
        rng,
        route_runtime.subscribe(),
        route_snapshot,
        0xfeed_beef,
    ));

    tokio::time::timeout(TokioDuration::from_secs(2), async {
        loop {
            if stats.get_current_connections_me() == 1 {
                break;
            }
            tokio::time::sleep(TokioDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("middle relay must increment route gauge before cutover");

    assert!(
        route_runtime.set_mode(RelayRouteMode::Direct).is_some(),
        "cutover must advance route generation"
    );

    let relay_result = tokio::time::timeout(TokioDuration::from_secs(6), relay_task)
        .await
        .expect("middle relay must terminate after cutover")
        .expect("middle relay task must not panic");
    assert!(
        relay_result.is_err(),
        "cutover should terminate middle relay session"
    );

    assert_eq!(
        stats.get_current_connections_me(),
        0,
        "route gauge must be released when middle relay exits on cutover"
    );

    drop(client_side);
}

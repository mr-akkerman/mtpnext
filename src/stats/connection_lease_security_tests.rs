use super::*;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn direct_connection_lease_balances_on_drop() {
    let stats = Arc::new(Stats::new());
    assert_eq!(stats.get_current_connections_direct(), 0);

    {
        let _lease = stats.acquire_direct_connection_lease();
        assert_eq!(stats.get_current_connections_direct(), 1);
    }

    assert_eq!(stats.get_current_connections_direct(), 0);
}

#[test]
fn middle_connection_lease_balances_on_drop() {
    let stats = Arc::new(Stats::new());
    assert_eq!(stats.get_current_connections_me(), 0);

    {
        let _lease = stats.acquire_me_connection_lease();
        assert_eq!(stats.get_current_connections_me(), 1);
    }

    assert_eq!(stats.get_current_connections_me(), 0);
}

#[test]
fn connection_lease_disarm_prevents_double_release() {
    let stats = Arc::new(Stats::new());

    let mut lease = stats.acquire_direct_connection_lease();
    assert_eq!(stats.get_current_connections_direct(), 1);

    stats.decrement_current_connections_direct();
    assert_eq!(stats.get_current_connections_direct(), 0);

    lease.disarm();
    drop(lease);

    assert_eq!(stats.get_current_connections_direct(), 0);
}

#[test]
fn direct_connection_lease_balances_on_panic_unwind() {
    let stats = Arc::new(Stats::new());
    let stats_for_panic = stats.clone();

    let panic_result = panic::catch_unwind(AssertUnwindSafe(move || {
        let _lease = stats_for_panic.acquire_direct_connection_lease();
        panic!("intentional panic to verify lease drop path");
    }));

    assert!(panic_result.is_err(), "panic must propagate from test closure");
    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "panic unwind must release direct route gauge"
    );
}

#[tokio::test]
async fn direct_connection_lease_balances_on_task_abort() {
    let stats = Arc::new(Stats::new());
    let stats_for_task = stats.clone();

    let task = tokio::spawn(async move {
        let _lease = stats_for_task.acquire_direct_connection_lease();
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(stats.get_current_connections_direct(), 1);

    task.abort();
    let joined = task.await;
    assert!(joined.is_err(), "aborted task must return a join error");

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "aborted task must release direct route gauge"
    );
}

#[tokio::test]
async fn middle_connection_lease_balances_on_task_abort() {
    let stats = Arc::new(Stats::new());
    let stats_for_task = stats.clone();

    let task = tokio::spawn(async move {
        let _lease = stats_for_task.acquire_me_connection_lease();
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(stats.get_current_connections_me(), 1);

    task.abort();
    let joined = task.await;
    assert!(joined.is_err(), "aborted task must return a join error");

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        stats.get_current_connections_me(),
        0,
        "aborted task must release middle route gauge"
    );
}

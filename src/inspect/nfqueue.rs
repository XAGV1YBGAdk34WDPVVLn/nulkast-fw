use crate::api::WsEvent;
use crate::inspect::{inspect_ipv4_packet, PacketVerdict, SharedRuleEngine};
use crate::store::{StoreEvent, StoreWriter};
use nfq::{Queue, Verdict};
use tokio::sync::broadcast;

/// Spawn `queues` OS threads bound to Linux NFQUEUE 0..queues with fail-open enabled.
/// Each thread inspects raw IPv4 packets inline with zero GC pauses.
pub fn spawn_nfqueue_workers(
    queues: u16,
    engine: SharedRuleEngine,
    writer: StoreWriter,
    events_tx: broadcast::Sender<WsEvent>,
) {
    for qnum in 0..queues {
        let eng = engine.clone();
        let wr = writer.clone();
        let ev = events_tx.clone();
        std::thread::Builder::new()
            .name(format!("nfq-worker-{}", qnum))
            .spawn(move || {
                let mut queue = match Queue::open() {
                    Ok(q) => q,
                    Err(e) => {
                        eprintln!("nfqueue {}: failed to open ({}); IDS inline skipped", qnum, e);
                        return;
                    }
                };
                if let Err(e) = queue.bind(qnum) {
                    eprintln!("nfqueue {}: failed to bind ({}); IDS inline skipped", qnum, e);
                    return;
                }
                let _ = queue.set_fail_open(qnum, true);
                let _ = queue.set_copy_range(qnum, 2048);

                loop {
                    let mut msg = match queue.recv() {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("nfqueue {}: recv error: {}", qnum, e);
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            continue;
                        }
                    };

                    let outcome = match eng.read() {
                        Ok(guard) => inspect_ipv4_packet(msg.get_payload(), &guard),
                        Err(_) => {
                            msg.set_verdict(Verdict::Accept);
                            let _ = queue.verdict(msg);
                            continue;
                        }
                    };

                    match outcome.verdict {
                        PacketVerdict::Accept => msg.set_verdict(Verdict::Accept),
                        PacketVerdict::Drop => msg.set_verdict(Verdict::Drop),
                    }
                    let _ = queue.verdict(msg);

                    for alert in outcome.alerts {
                        let _ = ev.send(WsEvent::Alert(alert.clone()));
                        wr.try_send(StoreEvent::RecordAlert(alert));
                    }
                }
            })
            .ok();
    }
}

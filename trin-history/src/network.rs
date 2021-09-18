use discv5::kbucket::KBucketsTable;
use log::debug;
use rocksdb::DB;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use trin_core::portalnet::{
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol},
    protocol::{PortalnetConfig, PortalnetEvents},
    utp::UtpListener,
    U256,
};

/// History network layer on top of the overlay protocol. Encapsulates history network specific data and logic.
#[derive(Clone)]
pub struct HistoryNetwork {
    pub overlay: Arc<OverlayProtocol>,
}

impl HistoryNetwork {
    pub async fn new(
        discovery: Arc<RwLock<Discovery>>,
        db: Arc<DB>,
        portal_config: PortalnetConfig,
    ) -> Result<(Self, PortalnetEvents), String> {
        let config = OverlayConfig::default();
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            discovery.read().await.local_enr().node_id().into(),
            config.bucket_pending_timeout,
            config.max_incoming_per_bucket,
            config.table_filter,
            config.bucket_filter,
        )));
        let data_radius = Arc::new(RwLock::new(portal_config.data_radius));

        let protocol_receiver = discovery
            .write()
            .await
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string())
            .unwrap();

        let overlay = OverlayProtocol {
            discovery: Arc::clone(&discovery),
            data_radius,
            kbuckets,
        };

        let overlay = Arc::new(overlay);

        let utp_listener = UtpListener {
            discovery: Arc::clone(&discovery),
            utp_connections: HashMap::new(),
        };

        let events = PortalnetEvents {
            discovery: Arc::clone(&discovery),
            overlay: Arc::clone(&overlay),
            protocol_receiver,
            db,
            utp_listener,
        };

        let proto = Self {
            overlay: Arc::clone(&overlay),
        };

        Ok((proto, events))
    }

    /// Convenience call for testing, quick way to ping bootnodes
    pub async fn ping_bootnodes(&mut self) -> Result<(), String> {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        for enr in self
            .overlay
            .discovery
            .read()
            .await
            .discv5
            .table_entries_enr()
        {
            debug!("Pinging {} on portal history network", enr);
            let ping_result = self.overlay.send_ping(U256::from(u64::MAX), enr).await?;
            debug!("Portal history network Ping result: {:?}", ping_result);
        }
        Ok(())
    }
}
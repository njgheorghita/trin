use std::collections::HashMap;
use std::sync::Arc;

use log::info;
use tokio::sync::RwLock;

use ethportal_peertest::cli::PeertestConfig;
use ethportal_peertest::events::PortalnetEvents;
use ethportal_peertest::jsonrpc::{
    test_jsonrpc_endpoints_over_http, test_jsonrpc_endpoints_over_ipc,
};
use trin_core::locks::RwLoggingExt;
use trin_core::portalnet::{
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol},
    types::{PortalnetConfig, ProtocolId},
    utp::UtpListener,
    Enr, U256,
};
use trin_core::utils::db::setup_overlay_db;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    tokio::spawn(async move {
        let peertest_config = PeertestConfig::default();
        let target_node: Enr = peertest_config.target_node.parse().unwrap();
        let portal_config = PortalnetConfig {
            listen_port: peertest_config.listen_port,
            internal_ip: true,
            bootnode_enrs: vec![target_node],
            ..Default::default()
        };

        let discovery = Arc::new(RwLock::new(Discovery::new(portal_config).unwrap()));
        discovery.write_with_warn().await.start().await.unwrap();

        let db = Arc::new(setup_overlay_db(
            discovery.read_with_warn().await.local_enr().node_id(),
        ));

        let overlay = Arc::new(
            OverlayProtocol::new(
                OverlayConfig::default(),
                Arc::clone(&discovery),
                db,
                U256::max_value(),
            )
            .await,
        );

        let utp_listener = UtpListener {
            discovery: Arc::clone(&discovery),
            utp_connections: HashMap::new(),
        };

        let events = PortalnetEvents::new(Arc::clone(&overlay), utp_listener).await;

        tokio::spawn(events.process_discv5_requests());

        match peertest_config.target_transport.as_str() {
            "ipc" => test_jsonrpc_endpoints_over_ipc(peertest_config).await,
            "http" => test_jsonrpc_endpoints_over_http(peertest_config).await,
            _ => panic!(
                "Invalid target-transport provided: {:?}",
                peertest_config.target_transport
            ),
        }

        info!("All tests passed successfully!");
        std::process::exit(1);
    })
    .await
    .unwrap();

    // refactor this error handling
    Ok(())
}

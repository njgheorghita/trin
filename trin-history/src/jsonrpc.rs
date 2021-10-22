use crate::network::HistoryNetwork;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use trin_core::{jsonrpc::{endpoints::{HistoryEndpoint, Ping}, types::HistoryJsonRpcRequest}, portalnet::types::ProtocolKind};
use trin_core::portalnet::Enr;

/// Handles History network JSON-RPC requests
pub struct HistoryRequestHandler {
    pub network: Arc<RwLock<HistoryNetwork>>,
    pub history_rx: mpsc::UnboundedReceiver<HistoryJsonRpcRequest>,
}

impl HistoryRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(request) = self.history_rx.recv().await {
            match request.endpoint {
                HistoryEndpoint::DataRadius => {
                    let _ = request.resp.send(Ok(Value::String(
                        self.network
                            .read()
                            .await
                            .overlay
                            .data_radius
                            .read()
                            .await
                            .to_string(),
                    )));
                }
                HistoryEndpoint::Ping => {
                    let protocol = ProtocolKind::History;
                    let ping: Ping = Ping::from_params(request.params);
                    let payload = None;
                    let response = self.network
                            .read()
                            .await
                            .overlay
                            .ping(
                                ping.enr,
                                protocol,
                                payload,
                            )
                            .await;
                    match response {
                        Ok(val) => request.resp.send(Ok(Value::String(val))).unwrap(),
                        Err(msg) => request.resp.send(Err(msg.to_string())).unwrap(),
                    };
                    ()
                }
            }
        }
    }
}

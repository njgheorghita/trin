use std::sync::{Arc, RwLock};

use anyhow::anyhow;
use ethereum_types::H256;
use log::{info, warn};
use serde_json::{json, Value};
use ssz::{Decode, Encode};
use tree_hash::TreeHash;
use tokio::sync::mpsc;

use crate::{
    jsonrpc::{
        endpoints::HistoryEndpoint,
        types::{HistoryJsonRpcRequest, Params},
    },
    portalnet::{
        storage::{PortalStorage, PortalStorageConfig},
        types::content_key::{
            BlockHeader, HistoryContentKey, EpochAccumulator, MasterAccumulator as MasterAccumulatorKey, SszNone,
        },
    },
    types::{accumulator::MasterAccumulator, header::Header},
    utils::{bytes::hex_encode, provider::TrustedProvider},
};

/// Responsible for dispatching cross-overlay-network requests
/// for data to perform validation. Currently, it just proxies these requests
/// on to the trusted provider.
#[derive(Debug)]
pub struct HeaderOracle {
    pub trusted_provider: TrustedProvider,
    // We could simply store the main portal jsonrpc tx channel here, rather than each
    // individual channel. But my sense is that this will be more useful in terms of
    // determining which subnetworks are actually available.
    pub history_jsonrpc_tx: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    pub master_accumulator: MasterAccumulator,
    pub portal_storage: Arc<RwLock<PortalStorage>>,
    pub bridge_rx: mpsc::UnboundedReceiver<Header>,
}

impl HeaderOracle {
    pub fn new(
        trusted_provider: TrustedProvider,
        storage_config: PortalStorageConfig,
        bridge_rx: mpsc::UnboundedReceiver<Header>,
    ) -> Self {
        let portal_storage = Arc::new(RwLock::new(PortalStorage::new(storage_config).unwrap()));
        Self {
            trusted_provider,
            history_jsonrpc_tx: None,
            master_accumulator: MasterAccumulator::default(),
            portal_storage,
            bridge_rx,
        }
    }

    /// 1. Sample latest accumulator from 10 peers
    /// 2. Get latest master accumulator from portal storage
    /// 3. Update PortalStorage if new accumulator from network is latest
    /// 4. Set current master accumulator to latest
    pub async fn bootstrap(&mut self) {
        // Get latest master accumulator from AccumulatorDB
        let latest_macc_content_key =
            HistoryContentKey::MasterAccumulator(MasterAccumulatorKey::Latest(SszNone::new()));
        let latest_local_macc: &Option<Vec<u8>> = &self
            .portal_storage
            .as_ref()
            .read()
            .unwrap()
            .get(&latest_macc_content_key)
            .unwrap_or(None);
        let latest_local_macc = match latest_local_macc {
            Some(val) => MasterAccumulator::from_ssz_bytes(val).unwrap_or_default(),
            None => MasterAccumulator::default(),
        };
        info!("latest local macc: {:?}", latest_local_macc.latest_height());

        // Sample latest accumulator from 10 network peers
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = HistoryJsonRpcRequest {
            endpoint: HistoryEndpoint::SampleLatestMasterAccumulator,
            resp: resp_tx,
            params: Params::None,
        };
        let history_jsonrpc_tx = match self.history_jsonrpc_tx.as_ref() {
            Some(val) => val,
            None => {
                // use latest_local_macc if history jsonrpc is unavailable
                self.master_accumulator = latest_local_macc;
                return;
            }
        };
        history_jsonrpc_tx.send(request).unwrap();
        let latest_network_macc: MasterAccumulator = match resp_rx.recv().await {
            Some(val) => serde_json::from_value(val.unwrap()).unwrap_or_default(),
            None => MasterAccumulator::default(),
        };
        info!(
            "latest network macc: {:?}",
            latest_network_macc.latest_height()
        );

        // Update portal storage with latest network macc if network macc is latest
        if latest_local_macc.latest_height() >= latest_network_macc.latest_height() {
            self.master_accumulator = latest_local_macc.clone();
        } else {
            self.master_accumulator = latest_network_macc.clone();
            self.write_macc_to_portal_storage(latest_network_macc);
        }
    }

    // 1. listen to "bridge" (aka hg network later) for new headers over channel
    //  - we do NOT need to forward headers to history network
    // 2. new header received..
    //  - if next, update macc
    //  - else, start "catchup()"
    // 3. "catchup()" ->
    pub async fn listen_for_new_headers(&mut self) {
        loop {
            tokio::select! {
                Some(header) = self.bridge_rx.recv() => {
                    info!("handling new header");
                    self.handle_new_header(header).await;
                }
            }
        }
    }

    // todo: double check that all offered content has the chance to be stored locally
    async fn handle_new_header(&mut self, header: Header) {
        // write to portal storage if should...
        let content_key = HistoryContentKey::BlockHeader(BlockHeader {
            chain_id: 1,
            block_hash: header.hash().to_fixed_bytes(),
        });
        let content: Vec<u8> = rlp::encode(&header).into();
        let _ = self
            .portal_storage
            .as_ref()
            .write()
            .unwrap()
            .store_if_should(&content_key, &content);
        match self.update_master_accumulator(&header) {
            Ok(_) => (),
            Err(_) => self.catchup_macc().await,
        }
    }

    // relies upon a trusted provider for now. todo: replace w/ chain history network
    async fn catchup_macc(&mut self) {
        // move to trusted_provider
        let params = Params::Array(vec![json!("latest".to_string()), json!(false)]);
        let method = "eth_getBlockByNumber".to_string();
        let response = self
            .trusted_provider
            .dispatch_http_request(method, params)
            .unwrap();
        let latest_header = Header::from_get_block_jsonrpc_response(response).unwrap();
        let mut height_delta = latest_header.number - self.master_accumulator.latest_height();
        while height_delta > 0 {
            info!(
                "building macc: # {:?}",
                self.master_accumulator.latest_height()
            );
            // 01x vs 02x?
            let block_number = format!("0x{:01X}", self.master_accumulator.latest_height());
            let params = Params::Array(vec![json!(block_number), json!(false)]);
            let method = "eth_getBlockByNumber".to_string();
            let response = self
                .trusted_provider
                .dispatch_http_request(method, params)
                .unwrap();
            let header = Header::from_get_block_jsonrpc_response(response).unwrap();
            match self.master_accumulator.update_accumulator(&header) {
                Ok(_) => (),
                Err(msg) => warn!("fuc: {:?}", msg),
            }
            self.write_macc_to_portal_storage(self.master_accumulator.clone());
            height_delta = latest_header.number - self.master_accumulator.latest_height();
        }
    }

    fn update_master_accumulator(&mut self, header: &Header) -> anyhow::Result<()> {
        if let Ok(Some(epoch_acc)) = self.master_accumulator.update_accumulator(header) {
            let content_key: Vec<u8> = HistoryContentKey::EpochAccumulator(EpochAccumulator{
                epoch_hash: epoch_acc.tree_hash_root(),
            }).into();
            let endpoint = HistoryEndpoint::Offer;
            let content = hex_encode(&epoch_acc.as_ssz_bytes());
            let params = Params::Array(vec![json!(content_key), json!(content)]);
            let (resp_tx, mut _resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
            let request = HistoryJsonRpcRequest {
                endpoint,
                resp: resp_tx,
                params,
            };
            // unwrap?
            // ignore response
            self.history_jsonrpc_tx.as_ref().unwrap().send(request).unwrap();
        };
        Ok(())
    }

    fn write_macc_to_portal_storage(&self, macc: MasterAccumulator) {
        let latest_macc_content_key =
            HistoryContentKey::MasterAccumulator(MasterAccumulatorKey::Latest(SszNone::new()));
        let _ = self
            .portal_storage
            .as_ref()
            .write()
            .unwrap()
            .store(&latest_macc_content_key, &macc.as_ssz_bytes());
    }

    // Currently falls back to trusted provider, to be updated to use canonical block indices network.
    pub fn get_hash_at_height(&self, block_number: u64) -> anyhow::Result<String> {
        let hex_number = format!("0x{:02X}", block_number);
        let method = "eth_getBlockByNumber".to_string();
        let params = Params::Array(vec![json!(hex_number), json!(false)]);
        let response: Value = self
            .trusted_provider
            .dispatch_http_request(method, params)?;
        let hash = match response["result"]["hash"].as_str() {
            Some(val) => val.trim_start_matches("0x"),
            None => {
                return Err(anyhow!(
                    "Unable to validate content received from trusted provider."
                ))
            }
        };
        Ok(hash.to_owned())
    }

    pub fn get_header_by_hash(&self, block_hash: H256) -> anyhow::Result<Header> {
        let block_hash = format!("0x{:02X}", block_hash);
        let method = "eth_getBlockByHash".to_string();
        let params = Params::Array(vec![json!(block_hash), json!(false)]);
        let response: Value = self
            .trusted_provider
            .dispatch_http_request(method, params)?;
        let header = Header::from_get_block_jsonrpc_response(response)?;
        Ok(header)
    }

    // To be updated to use chain history || header gossip network.
    pub fn _is_hash_canonical() -> anyhow::Result<bool> {
        Ok(true)
    }
}

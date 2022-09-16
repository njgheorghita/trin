use std::sync::{Arc, RwLock};

use anyhow::anyhow;
use async_trait::async_trait;
use ethereum_types::H256;
use serde_json::{json, Value};
use ssz::Decode;
use tokio::sync::mpsc;
use tracing::log::{info, warn};
use tree_hash::TreeHash;

use crate::{
    jsonrpc::endpoints::HistoryEndpoint,
    jsonrpc::types::{HistoryJsonRpcRequest, Params},
    portalnet::{
        storage::{ContentStore, PortalStorage, PortalStorageConfig},
        types::content_key::{
            HistoryContentKey, IdentityContentKey, MasterAccumulator as MasterAccumulatorKey,
            SszNone,
        },
    },
    types::{accumulator::{validate_pre_merge_header, MasterAccumulator}, header::Header},
    utils::{
        bytes::{hex_decode, hex_encode},
        provider::TrustedProvider,
    },
};

// todo: update once mainnet master_acc has synced
pub const MERGE_BLOCK_NUMBER: u64 = 274300u64;
//15_537_393

/// Responsible for dispatching cross-overlay-network requests
/// for data to perform validation. Currently, it just proxies these requests
/// on to the trusted provider.
#[derive(Clone, Debug)]
pub struct HeaderOracle {
    pub trusted_provider: TrustedProvider,
    // We could simply store the main portal jsonrpc tx channel here, rather than each
    // individual channel. But my sense is that this will be more useful in terms of
    // determining which subnetworks are actually available.
    pub history_jsonrpc_tx: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    pub master_acc: MasterAccumulator,
    pub portal_storage: Arc<RwLock<PortalStorage>>,
}

impl HeaderOracle {
    pub fn new(trusted_provider: TrustedProvider, storage_config: PortalStorageConfig) -> Self {
        let portal_storage = Arc::new(RwLock::new(PortalStorage::new(storage_config).unwrap()));
        Self {
            trusted_provider,
            history_jsonrpc_tx: None,
            master_accumulator: MasterAccumulator::default(),
            portal_storage,
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

        // Set current macc to latest macc
        self.master_accumulator = latest_local_macc.clone();

        // Update portal storage with latest network macc if network macc is latest
        if latest_local_macc.latest_height() < latest_network_macc.latest_height() {
            let _ = &self
                .portal_storage
                .as_ref()
                .write()
                .unwrap()
                .put(latest_macc_content_key, &latest_local_macc.as_ssz_bytes());
        }
    }

    pub async fn bootstrap(&mut self, trusted_master_acc_hash: H256) {
        // Get latest master accumulator from AccumulatorDB
        let latest_master_acc_content_key =
            HistoryContentKey::MasterAccumulator(MasterAccumulatorKey::Latest(SszNone::new()));
        let latest_local_master_acc: &Option<Vec<u8>> = &self
            .portal_storage
            .as_ref()
            .read()
            .unwrap()
            .get(&latest_master_acc_content_key)
            .unwrap_or(None);
        let latest_local_master_acc = match latest_local_master_acc {
            Some(val) => MasterAccumulator::from_ssz_bytes(val).unwrap_or_default(),
            None => {
                warn!("Unable to load default trusted master acc from portal storage");
                return;
            }
        };
        if latest_local_master_acc.tree_hash_root() == trusted_master_acc_hash {
            info!("Bootstrapping header oracle with default master accumulator.");
            self.master_acc = latest_local_master_acc;
            return;
        }

        // lookup up custom master acc from network
        let content_key: Vec<u8> = HistoryContentKey::MasterAccumulator(
            MasterAccumulatorKey::MasterHash(trusted_master_acc_hash),
        )
        .into();
        let content_key = hex_encode(content_key);
        let endpoint = HistoryEndpoint::RecursiveFindContent;
        let params = Params::Array(vec![json!(content_key)]);
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = HistoryJsonRpcRequest {
            endpoint,
            resp: resp_tx,
            params,
        };
        self.history_jsonrpc_tx().unwrap().send(request).unwrap();
        let master_acc_ssz = match resp_rx.recv().await {
            Some(val) => val,
            None => {
                warn!("Unable to bootstrap master acc: No response from chain history subnetwork");
                return;
            }
        };
        let master_acc_ssz = match master_acc_ssz {
            Ok(result) => result,
            Err(msg) => {
                warn!("Unable to bootstrap master acc: Error returned from chain history subnetwork: {msg:?}");
                return;
            }
        };
        let master_acc_ssz = match master_acc_ssz.as_str() {
            Some(val) => val,
            None => {
                warn!("Unable to bootstrap master acc: Invalid master accumulator received from chain history network");
                return;
            }
        };
        let trusted_master_acc_ssz = hex_decode(master_acc_ssz).unwrap();
        let trusted_master_acc =
            MasterAccumulator::from_ssz_bytes(&trusted_master_acc_ssz).unwrap();

        self.master_acc = trusted_master_acc;
        let _ = &self
            .portal_storage
            .as_ref()
            .write()
            .unwrap()
            .store(&latest_master_acc_content_key, &trusted_master_acc_ssz)
            .unwrap();
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

    fn history_jsonrpc_tx(&self) -> anyhow::Result<mpsc::UnboundedSender<HistoryJsonRpcRequest>> {
        match self.history_jsonrpc_tx.clone() {
            Some(val) => Ok(val),
            None => Err(anyhow!("History subnetwork is not available")),
        }
    }

    pub async fn validate_header_is_canonical(&self, header: Header) -> anyhow::Result<()> {
        if header.number > MERGE_BLOCK_NUMBER {
            if let Ok(val) =
                validate_pre_merge_header(&header, &self.master_acc, self.history_jsonrpc_tx()?)
                    .await
            {
                match val {
                    true => return Ok(()),
                    false => return Err(anyhow!("hash is invalid")),
                }
            }
        }
        // either header is post-merge or there was an error trying to validate it via chain
        // history network, so we fallback to infura
        let trusted_hash = self.get_hash_at_height(header.number).unwrap();
        let trusted_hash = H256::from_slice(&hex_decode(&trusted_hash)?);
        match trusted_hash == header.hash() {
            true => Ok(()),
            false => Err(anyhow!(
                "Content validation failed. Found: {:?} - Expected: {:?}",
                header.hash(),
                trusted_hash
            )),
        }
    }
}

/// Used by all overlay-network Validators to validate content in the overlay service.
#[async_trait]
pub trait Validator<TContentKey> {
    async fn validate_content(
        &self,
        content_key: &TContentKey,
        content: &[u8],
    ) -> anyhow::Result<()>
    where
        TContentKey: 'async_trait;
}

/// For use in tests where no validation needs to be performed.
pub struct MockValidator {}

#[async_trait]
impl Validator<IdentityContentKey> for MockValidator {
    async fn validate_content(
        &self,
        _content_key: &IdentityContentKey,
        _content: &[u8],
    ) -> anyhow::Result<()>
    where
        IdentityContentKey: 'async_trait,
    {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use discv5::enr::NodeId;

    use crate::cli::TrinConfig;
    use crate::portalnet::storage::PortalStorageConfig;

    #[test]
    fn header_oracle_bootstraps_with_frozen_macc() {
        let node_id = NodeId::random();
        let trin_config = TrinConfig::default();
        let trusted_provider = TrustedProvider::from_trin_config(&trin_config);
        let storage_config = PortalStorageConfig::new(100, node_id);
        let header_oracle = HeaderOracle::new(trusted_provider, storage_config);
        assert_eq!(header_oracle.master_acc.latest_height(), MERGE_BLOCK_NUMBER);
    }
}

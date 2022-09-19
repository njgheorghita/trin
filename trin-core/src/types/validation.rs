use std::str::FromStr;
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
    types::{
        accumulator::{validate_pre_merge_header, MasterAccumulator},
        header::Header,
    },
    utils::{
        bytes::{hex_decode, hex_encode},
        provider::TrustedProvider,
    },
};

pub const MERGE_BLOCK_NUMBER: u64 = 15_537_394u64;

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
            master_acc: MasterAccumulator::default(),
            portal_storage,
        }
    }

    /// Loads default master acc from disk, unless instructed to lookup a custom master acc
    /// from the network.
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

        info!("Bootstrapping header oracle with custom master accumulator.");
        self.master_acc = trusted_master_acc;
        let _ = &self
            .portal_storage
            .as_ref()
            .write()
            .unwrap()
            .put(latest_master_acc_content_key, trusted_master_acc_ssz)
            .unwrap();
    }

    // Currently falls back to trusted provider, to be updated to use canonical block indices network.
    pub fn get_hash_at_height(&self, block_number: u64) -> anyhow::Result<H256> {
        let hex_number = format!("0x{:02X}", block_number);
        let method = "eth_getBlockByNumber".to_string();
        let params = Params::Array(vec![json!(hex_number), json!(false)]);
        let response: Value = self
            .trusted_provider
            .dispatch_http_request(method, params)?;
        match response["result"]["hash"].as_str() {
            Some(val) => Ok(H256::from_str(val)?),
            None => Err(anyhow!(
                "Unable to validate content received from trusted provider."
            )),
        }
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
        if header.number <= MERGE_BLOCK_NUMBER {
            if let Ok(history_jsonrpc_tx) = self.history_jsonrpc_tx() {
                if let Ok(val) =
                    validate_pre_merge_header(&header, &self.master_acc, history_jsonrpc_tx).await
                {
                    match val {
                        true => return Ok(()),
                        false => return Err(anyhow!("hash is invalid")),
                    }
                }
            }
        }
        // either header is post-merge or there was an error trying to validate it via chain
        // history network, so we fallback to infura
        let trusted_hash = self.get_hash_at_height(header.number).unwrap();
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
    use std::str::FromStr;

    use discv5::enr::NodeId;

    use crate::cli::{TrinConfig, DEFAULT_MASTER_ACC_HASH};
    use crate::portalnet::storage::PortalStorageConfig;

    #[tokio::test]
    async fn header_oracle_bootstraps_with_default_merge_master_acc() {
        let node_id = NodeId::random();
        let trin_config = TrinConfig::default();
        let trusted_provider = TrustedProvider::from_trin_config(&trin_config);
        let storage_config = PortalStorageConfig::new(100, node_id);
        let mut header_oracle = HeaderOracle::new(trusted_provider, storage_config);
        header_oracle
            .bootstrap(trin_config.trusted_master_acc_hash)
            .await;
        assert_eq!(
            header_oracle.master_acc.height().unwrap(),
            MERGE_BLOCK_NUMBER
        );
        assert_eq!(
            header_oracle.master_acc.tree_hash_root(),
            H256::from_str(DEFAULT_MASTER_ACC_HASH).unwrap(),
        );
    }
}

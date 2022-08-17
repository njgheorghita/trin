use std::path::PathBuf;
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use discv5::enr::NodeId;
use ethereum_types::H256;
use rocksdb::{Options, DB};
use serde_json::{json, Value};
use ssz::Decode;

use crate::{
    jsonrpc::{
        endpoints::HistoryEndpoint, 
        handlers::proxy_query_to_history_subnet,
        service::dispatch_infura_request,
        types::{HistoryJsonRpcRequest, JsonRequest, Params},
    },
    portalnet::types::content_key::EpochAccumulator as EpochAccumulatorKey,
    portalnet::types::content_key::{BlockHeader, HistoryContentKey, IdentityContentKey, OverlayContentKey},
    types::accumulator::{AccumulatorDB, EpochAccumulator, MasterAccumulator, EPOCH_SIZE},
    types::header::Header,
    utils::db::get_data_dir,
};


const VALIDATION_TIMEOUT: u8 = 30; // seconds

/// Responsible for dispatching cross-overlay-network requests
/// for data to perform validation. Currently, it just proxies these requests
/// on to infura.
#[derive(Debug, Clone)]
pub struct HeaderOracle {
    pub infura_url: String,
    // We could simply store the main portal jsonrpc tx channel here, rather than each
    // individual channel. But my sense is that this will be more useful in terms of
    // determining which subnetworks are actually available.
    pub history_jsonrpc_tx: Option<tokio::sync::mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    pub master_accumulator: MasterAccumulator,
    pub accumulator_db: Arc<AccumulatorDB>,
}

impl HeaderOracle {
    pub fn init(infura_url: String, node_id: NodeId) -> Self {
        // utils/db::setup_rocksdb
        // 
        // db functions
        // - get latest master
        // - build longest possible master
        // - use infura if acc not up to date
        //
        let mut data_path: PathBuf = get_data_dir(node_id);
        data_path.push("accumulatordb");
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        let accumulator_db = Arc::new(AccumulatorDB{db: DB::open(&db_opts, data_path).unwrap()});
        let master_accumulator = accumulator_db.get_latest_master();
        Self {
            infura_url,
            master_accumulator,
            accumulator_db,
            history_jsonrpc_tx: None,
        }
    }
}

fn make_infura_request(params: Params, method: String, infura_url: &String) -> anyhow::Result<Value> {
    let request = JsonRequest {
        jsonrpc: "2.0".to_string(),
        params,
        method,
        id: 1, // ??
    };
    match dispatch_infura_request(request, infura_url) {
        Ok(val) => match serde_json::from_str(&val) {
            Ok(val) => Ok(val),
            Err(msg) => {
                return Err(anyhow!("Unable to validate content with Infura: {:?}", msg))
            }
        },
        Err(msg) => return Err(anyhow!("Unable to validate content with Infura: {:?}", msg)),
    }
}

impl HeaderOracle {
    // Currently falls back to infura, to be updated to use canonical block indices network.
    pub fn get_hash_at_height(&self, block_number: u64) -> anyhow::Result<String> {
        let hex_number = format!("0x{:02X}", block_number);
        let request = JsonRequest {
            jsonrpc: "2.0".to_string(),
            params: Params::Array(vec![json!(hex_number), json!(false)]),
            method: "eth_getBlockByNumber".to_string(),
            id: 1,
        };
        let response: Value = match dispatch_infura_request(request, &self.infura_url) {
            Ok(val) => match serde_json::from_str(&val) {
                Ok(val) => val,
                Err(msg) => {
                    return Err(anyhow!("Unable to validate content with Infura: {:?}", msg))
                }
            },
            Err(msg) => return Err(anyhow!("Unable to validate content with Infura: {:?}", msg)),
        };
        let infura_hash = match response["result"]["hash"].as_str() {
            Some(val) => val.trim_start_matches("0x"),
            None => {
                return Err(anyhow!(
                    "Unable to validate content with Infura: Invalid Infura response."
                ))
            }
        };
        Ok(infura_hash.to_owned())
    }

    pub fn get_header_by_hash(&self, block_hash: H256) -> anyhow::Result<Header> {
        let block_hash = format!("0x{:02X}", block_hash);
        let request = JsonRequest {
            jsonrpc: "2.0".to_string(),
            params: Params::Array(vec![json!(block_hash), json!(false)]),
            method: "eth_getBlockByHash".to_string(),
            id: 1,
        };
        let response: Value = match dispatch_infura_request(request, &self.infura_url) {
            Ok(val) => serde_json::from_str(&val)?,
            Err(msg) => {
                return Err(anyhow!(
                    "Unable to request validation data from Infura: {:?}",
                    msg
                ))
            }
        };
        let header = Header::from_get_block_jsonrpc_response(response)?;
        Ok(header)
    }

    // todo: confirm each macc update w/ network
    pub async fn build_master_accumulator(&mut self) {
        // i don't think the macc should be concerned with PortalStorage...
        // - aka headers/epochs fetched are irrevelent for PortalStorage.
        // - we will not lookup any values from PortalStorage. (at least for now)
        //
        //
        // todo:
        // should be able to start from empty macc
        // should be able to start from macc w/ n-1 epochs
        // should be able to start from macc in current epoch
        // - fetch headers needed to build out current epoch
        //
        //
        // starting with assumption that we always have latest up to date master locally stored /
        // available from network
        //
        let master = self.accumulator_db.get_latest_master();
        self.master_accumulator = master;
        // loop to fetch next header in queue
        loop {
            let target_header = self.master_accumulator.current_height() + 1;
            let block_number = format!("0x{:02X}", target_header);
            let params = Params::Array(vec![json!(block_number), json!(false)]);
            let infura_response = make_infura_request(params, "eth_getBlockByNumber".to_string(), &self.infura_url).unwrap();
            let block_hash = match infura_response["result"]["hash"].as_str() {
                Some(val) => val.trim_start_matches("0x"),
                None => panic!("fuck")
            };
            let block_hash = hex::decode(block_hash).unwrap();
            let mut hash_bytes: [u8; 32] = [0; 32];
            hash_bytes.copy_from_slice(&block_hash[..]);
            let content_key = HistoryContentKey::BlockHeader(BlockHeader {
                chain_id: 1,
                block_hash: hash_bytes,
            });
            let endpoint = HistoryEndpoint::RecursiveFindContent;
            let params = Params::Array(vec![json!(content_key.content_id())]);
            let response = proxy_query_to_history_subnet(&self.history_jsonrpc_tx.clone().unwrap(), endpoint, params).await.unwrap();
            let raw_header_bytes = match response["result"].as_str() {
                Some(val) => hex::decode(val.trim_start_matches("0x")).unwrap(),
                None => panic!("fuck")
            };
            let header: Header = rlp::decode(&raw_header_bytes).unwrap();
            self.master_accumulator.update_accumulator(&header, self.accumulator_db.clone());
        }
    }

    pub fn is_header_canonical(&self, header: Header) -> anyhow::Result<bool> {
        // todo: start timeout...
        // if fails, fallback to infura
        // infura id is guaranteed to be available
        match self
            .master_accumulator
            .header_in_current_epoch(&header.number)
        {
            true => {
                let rel_index = header.number - self.master_accumulator.historical_header_count();
                if rel_index
                    > (self.master_accumulator.current_epoch.header_records.len() as u64 - 1u64)
                {
                    return Ok(false);
                };
                let verified_block_hash = self.master_accumulator.current_epoch.header_records
                    [rel_index as usize]
                    .block_hash;
                Ok(verified_block_hash == header.hash())
            }
            false => {
                let epoch_index = self
                    .master_accumulator
                    .get_epoch_index(&(header.number as u64));
                let epoch_hash =
                    self.master_accumulator.historical_epochs.epochs[epoch_index as usize];
                let epoch_key: Vec<u8> =
                    HistoryContentKey::EpochAccumulator(EpochAccumulatorKey { epoch_hash }).into();
                // this is currently a stub db to mock the functionality of...
                // - a persistent db that will store the latest XXX epoch accumulators
                // - a channel to request a specific epoch accumulator from the chain history network
                let raw_epoch_accumulator = match self.accumulator_db.db.get(&epoch_key) {
                    Ok(val) => match val {
                        Some(val) => val,
                        // this is where we need to dip back into history network
                        None => return Err(anyhow!("fuck")),
                    },
                    Err(msg) => return Err(anyhow!("fuck: {:?}", msg)),
                };
                let epoch_accumulator =
                    EpochAccumulator::from_ssz_bytes(&raw_epoch_accumulator).unwrap();
                let header_index = (header.number as u64) - epoch_index * (EPOCH_SIZE as u64);
                let header_record = epoch_accumulator.header_records[header_index as usize];
                Ok(header_record.block_hash == header.hash())
            }
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

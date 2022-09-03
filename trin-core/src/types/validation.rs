use std::env;
use std::fs;
use std::io;
use std::sync::{Arc, RwLock};
use std::{thread, time};

use anyhow::anyhow;
use async_trait::async_trait;
use ethereum_types::H256;
use log::info;
use serde_json::{json, Value};
use ssz::{Decode, Encode};
use tokio::sync::mpsc;
use websocket::{url::Url, ClientBuilder, Message, OwnedMessage};

use crate::{
    jsonrpc::{
        endpoints::HistoryEndpoint,
        service::{dispatch_geth_request, dispatch_infura_request},
        types::{HistoryJsonRpcRequest, JsonRequest, Params},
    },
    portalnet::{
        storage::{PortalStorage, PortalStorageConfig},
        types::content_key::{
            BlockHeader, HistoryContentKey, IdentityContentKey,
            MasterAccumulator as MasterAccumulatorKey, SszNone,
        },
    },
    types::{accumulator::MasterAccumulator, header::Header},
    utils::{bytes::hex_encode, infura::build_infura_ws_url_from_env},
};

#[derive(Clone, Eq, PartialEq)]
pub enum ValidationProfile {
    Infura,
    InfuraMacc,
    Geth,
    GethMacc,
}

#[derive(Clone)]
pub struct GethProvider {
    pub geth_url: String,
}

#[derive(Clone)]
pub struct InfuraProvider {
    pub infura_url: String,
}

#[derive(Clone)]
pub enum TrustedProvider {
    Infura(InfuraProvider),
    Geth(GethProvider),
}

impl TrustedProvider {
    pub fn dispatch_request(&self, method: String, params: Params) -> anyhow::Result<Value> {
        let request = JsonRequest {
            jsonrpc: "2.0".to_string(),
            params,
            method,
            id: 1,
        };
        let response = match self {
            TrustedProvider::Infura(provider) => {
                match dispatch_infura_request(request, &provider.infura_url) {
                    Ok(val) => val,
                    Err(msg) => {
                        return Err(anyhow!(
                            "Unable to request validation data from Infura: {:?}",
                            msg
                        ))
                    }
                }
            }
            TrustedProvider::Geth(provider) => {
                match dispatch_geth_request(request, &provider.geth_url) {
                    Ok(val) => val,
                    Err(msg) => {
                        return Err(anyhow!(
                            "Unable to request validation data from Geth: {:?}",
                            msg
                        ))
                    }
                }
            }
        };
        Ok(serde_json::from_str(&response).map_err(|e| anyhow!(e))?)
    }
}

/// Responsible for dispatching cross-overlay-network requests
/// for data to perform validation. Currently, it just proxies these requests
/// on to infura.
#[derive(Clone)]
pub struct HeaderOracle {
    pub infura_url: String,
    // We could simply store the main portal jsonrpc tx channel here, rather than each
    // individual channel. But my sense is that this will be more useful in terms of
    // determining which subnetworks are actually available.
    pub history_jsonrpc_tx: Option<tokio::sync::mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    pub master_accumulator: MasterAccumulator,
    pub portal_storage: Arc<RwLock<PortalStorage>>,
    pub trusted_provider: TrustedProvider,
}

impl HeaderOracle {
    pub fn new(
        infura_url: String,
        storage_config: PortalStorageConfig,
        validation_profile: String,
    ) -> Self {
        let trusted_provider = match validation_profile.as_str() {
            "infura" => TrustedProvider::Infura(InfuraProvider {
                infura_url: infura_url.clone(),
            }),
            "geth" => TrustedProvider::Geth(GethProvider {
                geth_url: "https://mainnet-geth-prysm.ethpandaops.io/".to_string(),
            }),
            "infura/macc" => TrustedProvider::Infura(InfuraProvider {
                infura_url: infura_url.clone(),
            }),
            "geth/macc" => TrustedProvider::Geth(GethProvider {
                geth_url: "https://mainnet-geth-prysm.ethpandaops.io/".to_string(),
            }),
            _ => panic!("invalid validation profile"),
        };
        let portal_storage = Arc::new(RwLock::new(PortalStorage::new(storage_config).unwrap()));
        Self {
            infura_url,
            history_jsonrpc_tx: None,
            master_accumulator: MasterAccumulator::default(),
            portal_storage,
            trusted_provider,
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
        // Set current macc to latest local macc
        self.master_accumulator = latest_local_macc.clone();

        // Sample latest accumulator from 10 network peers
        let mut latest_network_macc = self.sample_network_macc().await;

        // max_threshold for bootstrapping
        let max_height_diff = 16;
        let mut current_delta =
            self.get_current_height().unwrap() - latest_network_macc.latest_height();
        // check overflow?
        /*        while current_delta > max_height_diff {*/
        //info!("macc height not caught up to threshold");
        //latest_network_macc = self.sample_network_macc().await;
        //current_delta =
        //self.get_current_height().unwrap() - latest_network_macc.latest_height();
        /*}*/

        // Update portal storage with latest network macc if network macc is latest
        if latest_local_macc.latest_height() < latest_network_macc.latest_height() {
            let _ = &self
                .portal_storage
                .as_ref()
                .write()
                .unwrap()
                .store(&latest_macc_content_key, &latest_local_macc.as_ssz_bytes());
        }
    }

    // Request 10 maccs from network peers
    async fn sample_network_macc(&self) -> MasterAccumulator {
        let endpoint = HistoryEndpoint::SampleLatestMasterAccumulator;
        let params = Params::None;
        match self.dispatch_chain_history_request(endpoint, params).await {
            Ok(val) => serde_json::from_value(val).unwrap_or_default(),
            Err(_) => MasterAccumulator::default(),
        }
    }

    pub async fn geth_build_macc(&mut self) {
        // update portal storage w/ macc
        // update portal storage w/ epoch acc?
        // offer epoch accs.
        let xxx = fs::read("./macc.txt").unwrap();
        let raw_macc = String::from_utf8_lossy(&xxx);
        let macc: MasterAccumulator = serde_json::from_str(&raw_macc).unwrap();
        self.master_accumulator = macc;
        let mut mainnet_height = self.get_current_height().unwrap();
        let mut current_delta = mainnet_height - self.master_accumulator.latest_height();
        info!("macc height: {:?}", self.master_accumulator.latest_height());
        info!("main height: {:?}", mainnet_height);
        info!("delta: {:?}", current_delta);
        thread::sleep(time::Duration::from_secs(10));
        loop {
            while current_delta > 0 {
                // use chain history network to build accumulator
                let next_header = self
                    .trusted_get_block(Some(self.master_accumulator.latest_height() + 1))
                    .unwrap();
                self.master_accumulator.update_accumulator(&next_header);
                current_delta = mainnet_height - self.master_accumulator.latest_height();
                // print to file
                let latest_height = self.master_accumulator.latest_height();
                if latest_height % 100 == 0 {
                    let mut data = format!("number: {:?}", latest_height);
                    data.push_str("---------");
                    data.push_str(
                        serde_json::to_string(&self.master_accumulator)
                            .unwrap()
                            .as_str(),
                    );
                    fs::write("./macc.txt", data).expect("fuck");
                }
            }
            thread::sleep(time::Duration::from_secs(10));
            mainnet_height = self.get_current_height().unwrap();
            current_delta = mainnet_height - self.master_accumulator.latest_height();
        }
    }

    pub async fn geth_build_macc_fancy(&mut self) {
        // update portal storage w/ macc
        // update portal storage w/ epoch acc?
        // offer epoch accs.
        let xxx = fs::read("./maccs/macc.txt").unwrap();
        let raw_macc = String::from_utf8_lossy(&xxx);
        let macc: MasterAccumulator = serde_json::from_str(&raw_macc).unwrap();
        self.master_accumulator = macc;
        let mut mainnet_height = self.get_current_height().unwrap();
        let mut current_delta = mainnet_height - self.master_accumulator.latest_height();
        info!("macc height: {:?}", self.master_accumulator.latest_height());
        info!("main height: {:?}", mainnet_height);
        info!("delta: {:?}", current_delta);
        thread::sleep(time::Duration::from_secs(10));
        loop {
            tokio::select! {
                Ok(resp) = self.fancy_0() => {
                    self.master_accumulator.update_accumulator(&resp);
                    // print to file
                    let latest_height = self.master_accumulator.latest_height();
                    if latest_height % 100 == 0 {
                        let data = serde_json::to_string(&self.master_accumulator)
                            .unwrap();
                        fs::write("./maccs/macc.txt", data.as_str()).expect("fuck");
                    }
                    info!("macc height: {:?}", self.master_accumulator.latest_height());
                }
                Ok(resp) = self.fancy_1() => {
                    self.master_accumulator.update_accumulator(&resp);
                    // print to file
                    let latest_height = self.master_accumulator.latest_height();
                    if latest_height % 100 == 0 {
                        let data = serde_json::to_string(&self.master_accumulator)
                            .unwrap();
                        fs::write("./maccs/macc.txt", data.as_str()).expect("fuck");
                    }
                    info!("macc height: {:?}", self.master_accumulator.latest_height());
                }
                Ok(resp) = self.fancy_2() => {
                    self.master_accumulator.update_accumulator(&resp);
                    // print to file
                    let latest_height = self.master_accumulator.latest_height();
                    if latest_height % 100 == 0 {
                        let data = serde_json::to_string(&self.master_accumulator)
                            .unwrap();
                        fs::write("./maccs/macc.txt", data.as_str()).expect("fuck");
                    }
                    info!("macc height: {:?}", self.master_accumulator.latest_height());
                }
                Ok(resp) = self.fancy_3() => {
                    self.master_accumulator.update_accumulator(&resp);
                    // print to file
                    let latest_height = self.master_accumulator.latest_height();
                    if latest_height % 100 == 0 {
                        let data = serde_json::to_string(&self.master_accumulator)
                            .unwrap();
                        fs::write("./maccs/macc.txt", data.as_str()).expect("fuck");
                    }
                    info!("macc height: {:?}", self.master_accumulator.latest_height());
                }
                Ok(resp) = self.fancy_4() => {
                    self.master_accumulator.update_accumulator(&resp);
                    // print to file
                    let latest_height = self.master_accumulator.latest_height();
                    if latest_height % 100 == 0 {
                        let data = serde_json::to_string(&self.master_accumulator)
                            .unwrap();
                        fs::write("./maccs/macc.txt", data.as_str()).expect("fuck");
                    }
                    info!("macc height: {:?}", self.master_accumulator.latest_height());
                }
                Ok(resp) = self.fancy_5() => {
                    self.master_accumulator.update_accumulator(&resp);
                    // print to file
                    let latest_height = self.master_accumulator.latest_height();
                    if latest_height % 100 == 0 {
                        let data = serde_json::to_string(&self.master_accumulator)
                            .unwrap();
                        fs::write("./maccs/macc.txt", data.as_str()).expect("fuck");
                    }
                    info!("macc height: {:?}", self.master_accumulator.latest_height());
                }
            }
        }
    }


    async fn fancy_0(&self) -> anyhow::Result<Header> {
        let url = "https://mainnet-geth-prysm.ethpandaops.io/".to_string();
        let block_number = Some(self.master_accumulator.latest_height() + 1);
        let response = tokio::task::spawn_blocking(move ||
            HeaderOracle::trusted_get_block_fancy(block_number, url).unwrap()
        ).await;
        match response {
            Ok(val) => Ok(val.clone()),
            Err(_) => Err(anyhow!("fuck"))
        }
    }

    async fn fancy_1(&self) -> anyhow::Result<Header> {
        let url = "https://mainnet-geth-nimbus.ethpandaops.io/".to_string();
        let block_number = Some(self.master_accumulator.latest_height() + 1);
        let response = tokio::task::spawn_blocking(move ||
            HeaderOracle::trusted_get_block_fancy(block_number, url).unwrap()
        ).await;
        match response {
            Ok(val) => Ok(val.clone()),
            Err(_) => Err(anyhow!("fuck"))
        }
    }

    async fn fancy_2(&self) -> anyhow::Result<Header> {
        let url = "https://mainnet-geth-teku.ethpandaops.io/".to_string();
        let block_number = Some(self.master_accumulator.latest_height() + 1);
        let response = tokio::task::spawn_blocking(move ||
            HeaderOracle::trusted_get_block_fancy(block_number, url).unwrap()
        ).await;
        match response {
            Ok(val) => Ok(val.clone()),
            Err(_) => Err(anyhow!("fuck"))
        }
    }

    async fn fancy_3(&self) -> anyhow::Result<Header> {
        let url = "https://mainnet-geth-lighthouse.ethpandaops.io/".to_string();
        let block_number = Some(self.master_accumulator.latest_height() + 1);
        let response = tokio::task::spawn_blocking(move ||
            HeaderOracle::trusted_get_block_fancy(block_number, url).unwrap()
        ).await;
        match response {
            Ok(val) => Ok(val.clone()),
            Err(_) => Err(anyhow!("fuck"))
        }
    }

    async fn fancy_4(&self) -> anyhow::Result<Header> {
        let url = "https://mainnet-geth-lodestar.ethpandaops.io/".to_string();
        let block_number = Some(self.master_accumulator.latest_height() + 1);
        let response = tokio::task::spawn_blocking(move ||
            HeaderOracle::trusted_get_block_fancy(block_number, url).unwrap()
        ).await;
        match response {
            Ok(val) => Ok(val.clone()),
            Err(_) => Err(anyhow!("fuck"))
        }
    }

    async fn fancy_5(&self) -> anyhow::Result<Header> {
        let url = "https://mainnet-erigon-lighthouse.ethpandaops.io/".to_string();
        let block_number = Some(self.master_accumulator.latest_height() + 1);
        let response = tokio::task::spawn_blocking(move ||
            HeaderOracle::trusted_get_block_fancy(block_number, url).unwrap()
        ).await;
        match response {
            Ok(val) => Ok(val.clone()),
            Err(_) => Err(anyhow!("fuck"))
        }
    }


    pub async fn infura_follow_head(&mut self) {
        let infura_url = build_infura_ws_url_from_env();
        let request = r#"{"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]}"#;
        let url = Url::parse(&infura_url).unwrap();
        let mut client = ClientBuilder::from_url(&url).connect(None).unwrap();
        client.send_message(&Message::text(request)).unwrap();
        for message in client.incoming_messages() {
            if let Ok(OwnedMessage::Text(val)) = message {
                let response: Value = serde_json::from_str(&val).unwrap();
                if let Some(val) = response.get("params") {
                    if let Ok(val) = Header::from_get_block_jsonrpc_response(val.clone()) {
                        let header = val;
                        println!("found header: {:?}", header);
                        self.master_accumulator.update_accumulator(&header);
                        // offer to network
                        // can we use PopulatedOffer here?
                        let content_key: Vec<u8> = HistoryContentKey::BlockHeader(BlockHeader {
                            chain_id: 1,
                            block_hash: header.hash().to_fixed_bytes(),
                        })
                        .into();
                        let header = hex_encode(rlp::encode(&header));
                        let content_key = hex_encode(content_key);
                        let endpoint = HistoryEndpoint::Offer;
                        let params = Params::Array(vec![json!(content_key), json!(header)]);
                        let _ = self.dispatch_chain_history_request(endpoint, params).await;
                        // todo: every X blocks update master acc in portal storage
                        // todo: occasional validation checks against peers maccs
                        // todo: only update accumulatordb if latest version is longer
                    } else {
                        println!("unable to decode infura header");
                    }
                }
            }
        }
    }

    // "trusted" = infura || geth
    // block_number = None for "latest"
    fn trusted_get_block_fancy(block_number: Option<u64>, geth_url: String) -> anyhow::Result<Header> {
        // 01X vs 02X?
        let block_arg = match block_number {
            Some(val) => format!("0x{:01X}", val),
            None => "latest".to_string(),
        };
        let params = Params::Array(vec![json!(block_arg), json!(false)]);
        let method = "eth_getBlockByNumber".to_string();
        let request = JsonRequest {
            jsonrpc: "2.0".to_string(),
            params,
            method,
            id: 1,
        };
        let response = match dispatch_geth_request(request, &geth_url) {
            Ok(val) => val,
            Err(msg) => {
                return Err(anyhow!(
                    "Unable to request validation data from Geth: {:?}",
                    msg
                ))
            }
        };
        let response = serde_json::from_str(&response).map_err(|e| anyhow!(e))?;
        Header::from_get_block_jsonrpc_response(response)
    }


    // "trusted" = infura || geth
    // block_number = None for "latest"
    fn trusted_get_block(&self, block_number: Option<u64>) -> anyhow::Result<Header> {
        // 01X vs 02X?
        let block_arg = match block_number {
            Some(val) => format!("0x{:01X}", val),
            None => "latest".to_string(),
        };
        let params = Params::Array(vec![json!(block_arg), json!(false)]);
        let method = "eth_getBlockByNumber".to_string();
        let response = self.trusted_provider.dispatch_request(method, params)?;
        Header::from_get_block_jsonrpc_response(response)
    }

    async fn chain_history_get_block(&self, number: u64) -> anyhow::Result<Header> {
        let block_hash = self.get_hash_at_height(number)?;
        let block_hash = H256::from_slice(&hex::decode(block_hash)?).to_fixed_bytes();
        let content_key = HistoryContentKey::BlockHeader(BlockHeader {
            chain_id: 1,
            block_hash,
        });
        let content_key: Vec<u8> = content_key.into();
        let content_key = hex_encode(content_key);
        let params = Params::Array(vec![json!(content_key)]);
        let endpoint = HistoryEndpoint::RecursiveFindContent;
        match self.dispatch_chain_history_request(endpoint, params).await {
            Ok(val) => Ok(Header::from_get_block_jsonrpc_response(val)?),
            Err(_) => Err(anyhow!("xx")),
        }
    }

    async fn dispatch_chain_history_request(
        &self,
        endpoint: HistoryEndpoint,
        params: Params,
    ) -> anyhow::Result<Value> {
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = HistoryJsonRpcRequest {
            endpoint,
            resp: resp_tx,
            params,
        };
        let history_jsonrpc_tx = self
            .history_jsonrpc_tx
            .as_ref()
            .ok_or_else(|| anyhow!("xx"))?;
        history_jsonrpc_tx.send(request).unwrap();
        match resp_rx.recv().await {
            Some(val) => Ok(val.unwrap()),
            None => Err(anyhow!("xx")),
        }
    }

    // Currently falls back to infura, to be updated to use canonical block indices network.
    pub fn get_hash_at_height(&self, block_number: u64) -> anyhow::Result<String> {
        let header = self.trusted_get_block(Some(block_number))?;
        Ok(header.hash().to_string())
    }

    fn get_current_height(&self) -> anyhow::Result<u64> {
        let params = Params::Array(vec![json!("latest"), json!(false)]);
        let method = "eth_getBlockByNumber".to_string();
        let response = self.trusted_provider.dispatch_request(method, params)?;
        let latest_height = match response["result"]["number"].as_str() {
            Some(val) => val.trim_start_matches("0x"),
            None => {
                return Err(anyhow!(
                    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    "Unable to validate content with Infura: Invalid Infura response."
                ));
            }
        };
        Ok(u64::from_str_radix(latest_height, 16)?)
    }

    pub fn get_header_by_hash(&self, block_hash: H256) -> anyhow::Result<Header> {
        let block_hash = format!("0x{:02X}", block_hash);
        let params = Params::Array(vec![json!(block_hash), json!(false)]);
        let method = "eth_getBlockByHash".to_string();
        let response = self.trusted_provider.dispatch_request(method, params)?;
        Header::from_get_block_jsonrpc_response(response)
    }

    // To be updated to use chain history || header gossip network.
    pub fn _is_hash_canonical() -> anyhow::Result<bool> {
        Ok(true)
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

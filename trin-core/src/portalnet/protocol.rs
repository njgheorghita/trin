#![allow(dead_code)]

use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use discv5::{Discv5ConfigBuilder, Discv5Event, TalkRequest};
use log::{debug, error, warn};
use rocksdb::{Options, DB};
use serde_json::Value;
use tokio::sync::mpsc;
use ssz_derive::{Decode, Encode};
use ssz;
use ssz::Encode;
use discv5::enr::NodeId;
use tiny_keccak::{Hasher, Keccak};
use ethereum_types::Address;
use hex;

use crate::utils::get_data_dir;

use super::{
    discovery::{Config as DiscoveryConfig, Discovery},
    overlay::{Config as OverlayConfig, Overlay},
    types::{
        FindContent, FindNodes, FoundContent, HexData, Nodes, Ping, Pong, Request, Response, SszEnr,
    },
    U256,
};
use super::{types::Message, Enr};
use crate::socket;

type Responder<T, E> = mpsc::UnboundedSender<Result<T, E>>;

#[derive(Debug)]
pub enum PortalEndpointKind {
    NodeInfo,
    RoutingTableInfo,
    EthGetBalance,
}

#[derive(Debug)]
pub struct PortalEndpoint {
    pub kind: PortalEndpointKind,
    pub params: Option<Vec<Value>>,
    pub resp: Responder<Value, String>,
    pub state_root: Option<String>,
}

#[derive(Clone)]
pub struct PortalnetConfig {
    pub external_addr: Option<SocketAddr>,
    pub private_key: Option<HexData>,
    pub listen_port: u16,
    pub bootnode_enrs: Vec<Enr>,
    pub data_radius: U256,
}

impl Default for PortalnetConfig {
    fn default() -> Self {
        Self {
            external_addr: None,
            private_key: None,
            listen_port: 4242,
            bootnode_enrs: Vec::<Enr>::new(),
            data_radius: U256::from(u64::MAX), //TODO better data_radius default?
        }
    }
}

pub const PROTOCOL: &str = "portal";

#[derive(Clone)]
pub struct PortalnetProtocol {
    pub discovery: Arc<Discovery>,
    pub overlay: Overlay,
}

pub struct PortalnetEvents {
    discovery: Arc<Discovery>,
    overlay: Overlay,
    protocol_receiver: mpsc::Receiver<Discv5Event>,
    db: DB,
}

pub struct JsonRpcHandler {
    pub discovery: Arc<Discovery>,
    pub jsonrpc_rx: mpsc::UnboundedReceiver<PortalEndpoint>,
}


#[derive()]
pub struct AccountProof{
    pub content_type: u8,
    pub address: String,
    pub state_root: String,
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct AccountProofContainer{
    pub address: CustomAddress,
    pub state_root: [u8; 32],
}


#[derive(Debug, PartialEq, Clone, Copy)]
pub struct CustomAddress(Address);

impl ssz::Encode for CustomAddress {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    //fn ssz_bytes_len(&self) -> usize {
        //20
    //}

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // get rid of 0
        buf.append(&mut self.0.as_bytes().to_vec());
    }
}

impl ssz::Decode for CustomAddress {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    //fn ssz_bytes_len(&self) -> usize {
        //20
    //}

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        // this is broken likely
        Ok(CustomAddress::new(Address::from_slice(bytes)))
    }
}

impl CustomAddress {
    pub fn new(address: Address) -> CustomAddress {
        CustomAddress(address)
    }
}

impl Deref for CustomAddress {
    type Target = Address;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CustomAddress {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

//impl ssz::Decode for Address {
    //fn is_ssz_fixed_len() -> bool {
        //true
    //}

    //fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        //let mut builder = ssz::SszDecoderBuilder::new(&bytes);
        //builder.register_type::<Address>().unwrap();
        //let mut decoder = builder.build()?;
        //Ok(Self {
            //bytes: decoder.decode_next()?,
        //})
    //}
//}


impl AccountProof{
    // 0x02 | Container(address: bytes20, state_root: bytes32)
    pub fn get_content_key(&self) -> Vec<u8> {
        let mut content_key = [2u8].to_vec();
        //let mut address_byte_array: [u8; 20] = Default::default();
        let decoded_address = hex::decode(&self.address).unwrap();
        //address_byte_array.copy_from_slice(&decoded_address[0..20]);

        let mut state_root_byte_array: [u8; 32] = Default::default();
        let decoded_state_root = hex::decode(&self.state_root).unwrap();
        state_root_byte_array.copy_from_slice(&decoded_state_root[0..32]);

        let bytes_address = CustomAddress::new(Address::from_slice(decoded_address.as_slice()));
        let ssz_container = AccountProofContainer{
            address: bytes_address,
            state_root: state_root_byte_array,
        };
        content_key.append(&mut ssz_container.as_ssz_bytes());
        content_key
        //self.state_root.to_vec()
    }

    // content_id = keccak(address)
    pub fn get_content_id(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut hasher = Keccak::v256();
        let decoded_address = hex::decode(&self.address).unwrap();
        hasher.update(decoded_address.as_slice());
        hasher.finalize(&mut out);
        out
    }
}

impl JsonRpcHandler {
    pub async fn process_jsonrpc_requests(mut self) {
        while let Some(cmd) = self.jsonrpc_rx.recv().await {
            use PortalEndpointKind::*;

            match cmd.kind {
                NodeInfo => {
                    let node_id = self.discovery.local_enr().to_base64();
                    let _ = cmd.resp.send(Ok(Value::String(node_id)));
                }
                RoutingTableInfo => {
                    let routing_table_info = self
                        .discovery
                        .discv5
                        .table_entries_id()
                        .iter()
                        .map(|node_id| Value::String(node_id.to_string()))
                        .collect();
                    let _ = cmd.resp.send(Ok(Value::Array(routing_table_info)));
                }
                EthGetBalance => {
                    // look up stateroot via header chain
                    // ``` state_root = proxy_to_infura('latest state root')
                    // start O(1) process and GND process (optional)
                    // ``` dispatch_state_network_request('eth_getBalance', address, state_root, Arc<discovery>)
                    // look up account proof by address
                    // - generate content key
                    // generate_account_trie_proof_content_key(address, state_root)
                    let addr = cmd.params.clone().unwrap()[0].as_str().unwrap().to_string();
                    let account_trie_proof = AccountProof{
                        content_type: 2u8,
                        address: addr,
                        state_root: cmd.state_root.unwrap(),
                    };
                    let content_key = account_trie_proof.get_content_key();
                    println!("content key: {:?}", content_key);
                    let content_id = account_trie_proof.get_content_id();
                    println!("content id: {:02X?}", content_id);
                    // - check local db
                    // portal_storage.get(content_id) // coming soon in pr

                    // - find node from network
                    let target_node_id = NodeId::new(&content_id);
                    let nodes = self.discovery.discv5.find_node(target_node_id);
                    // - req proof
                    // for node in node:
                    //     while not proof:
                    //          proof = get_proof_from_node() 
                    // - validate proof
                    // - return proof
                    let _ = cmd.resp.send(Ok(Value::String("100".to_string())));
                }
            }
        }
    }
}

impl PortalnetEvents {
    /// Receives a request from the talkreq handler and sends a response back
    pub async fn process_discv5_requests(mut self) {
        while let Some(event) = self.protocol_receiver.recv().await {
            debug!("Got discv5 event {:?}", event);

            let request = match event {
                Discv5Event::TalkRequest(r) => r,
                _ => continue,
            };

            let reply = match self.process_one_request(&request).await {
                Ok(r) => Message::Response(r).to_bytes(),
                Err(e) => {
                    error!("failed to process portal event: {}", e);
                    e.into_bytes()
                }
            };

            if let Err(e) = request.respond(reply) {
                warn!("failed to send reply: {}", e);
            }
        }
    }

    async fn process_one_request(&self, talk_request: &TalkRequest) -> Result<Response, String> {
        let protocol = std::str::from_utf8(talk_request.protocol())
            .map_err(|_| "Invalid protocol".to_owned())?;

        if protocol != PROTOCOL {
            return Err("Invalid protocol".to_owned());
        }

        let request = match Message::from_bytes(talk_request.body()) {
            Ok(Message::Request(r)) => r,
            Ok(_) => return Err("Invalid message".to_owned()),
            Err(e) => return Err(format!("Invalid request: {}", e)),
        };

        let response = match request {
            Request::Ping(Ping { .. }) => {
                debug!("Got overlay ping request {:?}", request);
                let enr_seq = self.discovery.local_enr().seq();
                Response::Pong(Pong {
                    enr_seq: enr_seq,
                    data_radius: self.overlay.data_radius(),
                })
            }
            Request::FindNodes(FindNodes { distances }) => {
                let distances64: Vec<u64> = distances.iter().map(|x| (*x).into()).collect();
                let enrs = self.overlay.nodes_by_distance(distances64);
                Response::Nodes(Nodes {
                    // from spec: total = The total number of Nodes response messages being sent.
                    // TODO: support returning multiple messages
                    total: 1 as u8,
                    enrs,
                })
            }
            Request::FindContent(FindContent { content_key }) => match self.db.get(&content_key) {
                Ok(Some(value)) => {
                    let empty_enrs: Vec<SszEnr> = vec![];
                    Response::FoundContent(FoundContent {
                        enrs: empty_enrs,
                        payload: value,
                    })
                }
                Ok(None) => {
                    let enrs = self.overlay.find_nodes_close_to_content(content_key);
                    let empty_payload: Vec<u8> = vec![];
                    Response::FoundContent(FoundContent {
                        enrs: enrs,
                        payload: empty_payload,
                    })
                }
                Err(e) => panic!("Unable to respond to FindContent: {}", e),
            },
        };

        Ok(response)
    }
}

impl PortalnetProtocol {
    pub async fn new(portal_config: PortalnetConfig) -> Result<(Self, PortalnetEvents), String> {
        let listen_all_ips = SocketAddr::new("0.0.0.0".parse().unwrap(), portal_config.listen_port);

        let external_addr = portal_config
            .external_addr
            .or_else(|| socket::stun_for_external(&listen_all_ips))
            .unwrap_or_else(|| socket::default_local_address(portal_config.listen_port));

        let config = DiscoveryConfig {
            discv5_config: Discv5ConfigBuilder::default().build(),
            // This is for defining the ENR:
            listen_port: external_addr.port(),
            listen_address: external_addr.ip(),
            bootnode_enrs: portal_config.bootnode_enrs,
            private_key: portal_config.private_key,
            ..Default::default()
        };

        let mut discovery = Discovery::new(config).unwrap();
        discovery.start(listen_all_ips).await?;

        let protocol_receiver = discovery
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string())?;

        let overlay = Overlay::new(
            discovery.local_enr(),
            portal_config.data_radius,
            OverlayConfig::default(),
        );

        let discovery = Arc::new(discovery);
        let data_path = get_data_dir(discovery.local_enr());

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        let db = DB::open(&db_opts, data_path).unwrap();

        let events = PortalnetEvents {
            discovery: discovery.clone(),
            overlay: overlay.clone(),
            protocol_receiver,
            db,
        };

        let proto = Self {
            discovery: discovery.clone(),
            overlay: overlay.clone(),
        };

        Ok((proto, events))
    }

    pub async fn send_ping(&self, data_radius: U256, enr: Enr) -> Result<Vec<u8>, String> {
        let enr_seq = self.discovery.local_enr().seq();
        let msg = Ping {
            enr_seq,
            data_radius,
        };
        self.discovery
            .send_talkreq(
                enr,
                PROTOCOL.to_string(),
                Message::Request(Request::Ping(msg)).to_bytes(),
            )
            .await
    }

    pub async fn send_find_nodes(&self, distances: Vec<u16>, enr: Enr) -> Result<Vec<u8>, String> {
        let msg = FindNodes { distances };
        self.discovery
            .send_talkreq(
                enr,
                PROTOCOL.to_string(),
                Message::Request(Request::FindNodes(msg)).to_bytes(),
            )
            .await
    }

    pub async fn send_find_content(
        &self,
        content_key: Vec<u8>,
        enr: Enr,
    ) -> Result<Vec<u8>, String> {
        let msg = FindContent { content_key };
        self.discovery
            .send_talkreq(
                enr,
                PROTOCOL.to_string(),
                Message::Request(Request::FindContent(msg)).to_bytes(),
            )
            .await
    }

    /// Convenience call for testing, quick way to ping bootnodes
    pub async fn ping_bootnodes(&mut self) -> Result<(), String> {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        for enr in self.discovery.discv5.table_entries_enr() {
            debug!("Pinging {} on portal network", enr);
            let ping_result = self.send_ping(U256::from(u64::MAX), enr).await?;
            debug!("Portal network Ping result: {:?}", ping_result);
        }
        Ok(())
    }
}

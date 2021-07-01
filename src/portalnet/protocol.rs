#![allow(dead_code)]

use std::convert::TryInto;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use super::{
    discovery::{Config as DiscoveryConfig, Discovery},
    types::{FindContent, FindNodes, FoundContent, Nodes, Ping, Pong, Request, Response, SszEnr},
    utils::xor_two_values,
    U256,
};
use super::{types::Message, Enr};
use discv5::{Discv5ConfigBuilder, Discv5Event, TalkRequest};
use log::{debug, error, warn};
use rocksdb::{DB, IteratorMode, Options};
use tokio::sync::mpsc;

use super::socket;

#[derive(Clone)]
pub struct PortalnetConfig {
    pub external_addr: Option<SocketAddr>,
    pub listen_port: u16,
    pub bootnode_enrs: Vec<Enr>,
    pub data_radius: U256,
}

impl Default for PortalnetConfig {
    fn default() -> Self {
        Self {
            external_addr: None,
            listen_port: 4242,
            bootnode_enrs: vec![],
            data_radius: U256::from(u64::MAX), //TODO better data_radius default?
        }
    }
}

pub const PROTOCOL: &str = "portal";

pub struct PortalnetProtocol {
    discovery: Arc<Discovery>,
    data_radius: U256,
}

pub struct PortalnetEvents {
    data_radius: U256,
    discovery: Arc<Discovery>,
    protocol_receiver: mpsc::Receiver<Discv5Event>,
    db: DB,
}

impl PortalnetEvents {
    /// Receives a request from the talkreq handler and sends a response back
    pub async fn process_requests(mut self) {
        while let Some(event) = self.protocol_receiver.recv().await {
            debug!("Got discv5 event {:?}", event);

            let request = match event {
                Discv5Event::TalkRequest(r) => r,
                _ => continue,
            };

            let reply = match self.process_one_request(&request).await {
                Ok(r) => {
                    println!("--- init reply: {:?}", r);
                    Message::Response(r).to_bytes()
                },
                Err(e) => {
                    error!("failed to process portal event: {}", e);
                    e.into_bytes()
                }
            };
            println!("----- reply: {:?}", reply);

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
                    data_radius: self.data_radius,
                })
            }

            Request::FindNodes(FindNodes { distances }) => {
                let distances64: Vec<u64> = distances.iter().map(|x| (*x).into()).collect();
                let enrs = self.discovery.find_nodes_response(distances64);
                Response::Nodes(Nodes {
                // from spec: total: The total number of Nodes response messages being sent.
                // not number of enrs
                    total: 1 as u8,
                    enrs,
                })
            }
            // TODO
            Request::FindContent(FindContent { content_key }) => {
                println!("looking up: {:02X?}", content_key);
                match self.db.get(&content_key) {
                    Ok(Some(value)) => {
                        println!("---- found value: {:02X?}", value);
                        let empty_enrs: Vec<SszEnr> = vec![];
                        Response::FoundContent( FoundContent { enrs: empty_enrs, payload: value })
                    },
                    Ok(None) => {
                        println!("---- value not found");
                        let enrs = self.discovery.find_nodes_close_to_content(content_key);
                        let empty_payload: Vec<u8> = vec![];
                        Response::FoundContent( FoundContent { enrs: enrs, payload: empty_payload })
                    },
                    Err(e) => panic!("operational error encountered: {}", e),
                }
            }
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
            ..Default::default()
        };

        let mut discovery = Discovery::new(config).unwrap();
        discovery.start(listen_all_ips).await?;

        let protocol_receiver = discovery
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string())?;

        let discovery = Arc::new(discovery);

        let proto = Self {
            discovery: discovery.clone(),
            data_radius: portal_config.data_radius,
        };

        // preimage stuff here
        //

        fn demo<T, const N: usize>(v: Vec<T>) -> [T; N] {
            v.try_into()
                .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
        }


        let default_preimage_path = match env::var("TRIN_DUMP_DB_PATH") {
            Ok(val) => val,
            Err(_) => panic!(
                "Must supply Infura key as environment variable, like:\n\
                TRIN_DUMP_DB_PATH=\"/path\" trin"
            ),
        };

        println!("doing preimage lookup");
        let node_id = proto.discovery.discv5.local_enr().node_id().raw();
        let node_id_vector = node_id.iter().cloned().collect();
        println!("i am {:02X?}", node_id);
        println!("data radius: {}", portal_config.data_radius);
        let half_data_radius = U256::MAX / 2;
        println!("half data radius: {}", half_data_radius);
        let db = DB::open_default(default_preimage_path).unwrap();
        let mut iter = db.iterator(IteratorMode::Start);
        let mut count = 0;
        let mut total_count = 0;
        for (key, value) in iter {
            let key_vector = (key as Box<[u8]>).into_vec();
            let other_vector = key_vector.clone();
            let one_more_vector = key_vector.clone();
            let diff = xor_two_values(&node_id_vector, &key_vector);
            let other_diff = diff.clone();
            let thing: [u8; 32] = demo(diff);
            let other = U256::from_big_endian(&thing);
            if other < half_data_radius {
                //if count < 5 {
                    //println!("Saw {:02X?} : {:02X?}", other_vector, value);
                //}
                //println!("key: {:02X?}", one_more_vector); 
                //println!("diff: {:02X?}", other_diff); 
                //println!("u256: {:?}", other); 
                count += 1;
            } else {
                //println!(" skipping content key");
            }
            total_count += 1;
        }
        println!("lookup finished: added {:?} values out of {:?}", count, total_count);

        let events = PortalnetEvents {
            data_radius: portal_config.data_radius,
            discovery,
            protocol_receiver,
            db,
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
            .send_talkreq(enr, Message::Request(Request::Ping(msg)).to_bytes())
            .await
    }

    pub async fn send_find_nodes(&self, distances: Vec<u16>, enr: Enr) -> Result<Vec<u8>, String> {
        let msg = FindNodes { distances };
        self.discovery
            .send_talkreq(enr, Message::Request(Request::FindNodes(msg)).to_bytes())
            .await
    }

    pub async fn send_find_content(
        &self,
        content_key: Vec<u8>,
        enr: Enr,
    ) -> Result<Vec<u8>, String> {
        let msg = FindContent { content_key };
        self.discovery
            .send_talkreq(enr, Message::Request(Request::FindContent(msg)).to_bytes())
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

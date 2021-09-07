use trin_core::portalnet::protocol::PortalnetConfig;
use trin_core::portalnet::discovery::{Config, Discovery};
use trin_core::portalnet::types::{Ping, Pong};


const STATE_NETWORK_PROTOCOL_ID: &str = "portal-state";
// todo: get rid of
const STATE_NETWORK_DISCOVERY_PORT: u16 = 9001;

pub struct StatePortalProtocol {
    pub base_discovery: Discovery,
    pub subnet_discovery: Discovery,
    pub portalnet_config: PortalnetConfig,
}

pub struct StateProtocolEvents;

impl StatePortalProtocol {
    pub fn new(discovery: Discovery, portalnet_config: PortalnetConfig) -> (Self, StateProtocolEvents) {

        let bootnodes: Vec<Enr> = [].to_vec();
        while bootnodes.len() < 1 {
            let all_peers = discovery.connected_peers();
            for peer in all_peers {
                let enr = self.discv5.find_enr(&peer).unwrap();
                let ping = Ping{
                    enr_seq: enr.seq(),
                    // update this to state-specific data radius
                    data_radius: portalnet_config.data_radius,
                };
                let ping_request: Vec<u8> = ping.encode();
                let response = self.send_talkreq(enr, PROTOCOL.to_string(), request).await;
                match Pong::from_ssz_bytes(response) {
                    Ok(val) => bootnodes.append(enr),
                    Err(_) => (),
                }
            }
        }

        let overlay_config = Config {
            listen_port: STATE_NETWORK_DISCOVERY_PORT,
            private_key: portalnet_config.private_key.clone(),
            listen_address: portalnet_config.external_addr.unwrap().ip(),
            bootnode_enrs: bootnodes,
            ..Config::default()
        };
        let overlay_discovery = Discovery::new(overlay_config).unwrap();
        let protocol = StatePortalProtocol{
            base_discovery: discovery,
            subnet_discovery: overlay_discovery,
            portalnet_config
        };
        let events = StateProtocolEvents{};
        (protocol, events)
    }
}

use rlp::{Encodable, Decodable};
use std::str::FromStr;
use std::ops::{Deref, DerefMut};

use ssz::{Decode, DecodeError, Encode, SszEncoder, SszDecoderBuilder};
use ssz;
use discv5::enr::CombinedKey;
use discv5::enr::EnrBuilder;
use std::net::Ipv4Addr;

use ssz_derive::{Decode, Encode};

use std::convert::{TryFrom, TryInto};

use super::{Enr, U256};

#[derive(Debug, PartialEq, Clone)]
pub struct ProtocolMessage {
    message_id: u8,
    encoded_message: Message,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Message {
    Request(Request),
    Response(Response),
}

impl Message {
    /// Return the byte representation of the Message by prefixing the `message_id`
    /// with the message payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Message::Request(req) => {
                let mut payload = vec![req.message_id()];
                match req {
                    Request::Ping(p) => payload.append(&mut p.as_ssz_bytes()),
                    Request::FindNodes(p) => payload.append(&mut p.as_ssz_bytes()),
                    Request::FindContent(p) => payload.append(&mut p.as_ssz_bytes()),
                }
                payload
            }
            Message::Response(resp) => {
                let mut payload = vec![resp.message_id()];
                match resp {
                    Response::Pong(p) => payload.append(&mut p.as_ssz_bytes()),
                    Response::Nodes(p) => payload.append(&mut p.as_ssz_bytes()),
                    Response::FoundContent(p) => payload.append(&mut p.as_ssz_bytes()),
                }
                payload
            }
        }
    }

    /// Decode a `Message` type from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if let Some(message_id) = bytes.first() {
            match message_id {
                // Requests
                1 => Ok(Message::Request(Request::Ping(
                    Ping::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| format!("Failed to decode ssz: {:?}", e))?,
                ))),
                3 => Ok(Message::Request(Request::FindNodes(
                    FindNodes::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| format!("Failed to decode ssz: {:?}", e))?,
                ))),
                5 => Ok(Message::Request(Request::FindContent(
                    FindContent::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| format!("Failed to decode ssz: {:?}", e))?,
                ))),
                2 => Ok(Message::Response(Response::Pong(
                    Pong::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| format!("Failed to decode ssz: {:?}", e))?,
                ))),
                4 => Ok(Message::Response(Response::Nodes(
                    Nodes::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| format!("Failed to decode ssz: {:?}", e))?,
                ))),
                6 => Ok(Message::Response(Response::FoundContent(
                    FoundContent::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| format!("Failed to decode ssz: {:?}", e))?,
                ))),
                _ => Err("Unknown message id".to_string()),
            }
        } else {
            Err("Empty bytes".to_string())
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Request {
    Ping(Ping),
    FindNodes(FindNodes),
    FindContent(FindContent),
}

impl Request {
    fn message_id(&self) -> u8 {
        match self {
            Request::Ping(_) => 1,
            Request::FindNodes(_) => 3,
            Request::FindContent(_) => 5,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Response {
    Pong(Pong),
    Nodes(Nodes),
    FoundContent(FoundContent),
}

impl Response {
    fn message_id(&self) -> u8 {
        match self {
            Response::Pong(_) => 2,
            Response::Nodes(_) => 4,
            Response::FoundContent(_) => 6,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Ping {
    pub enr_seq: u64,
    pub data_radius: U256,
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Pong {
    pub enr_seq: u64,
    pub data_radius: U256,
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct FindNodes {
    // TODO: Make this an ssz list
    pub distances: Vec<u16>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Nodes {
    pub total: u8,
    // TODO: Make this an ssz list
    pub enrs: Vec<Enr>,
}

#[derive(Debug, Encode, Decode)]
struct NodesHelper {
    total: u8,
    enrs: Vec<Vec<u8>>,
}

impl From<&Nodes> for NodesHelper {
    fn from(nodes: &Nodes) -> Self {
        Self {
            total: nodes.total,
            enrs: nodes
                .enrs
                .iter()
                .map(|enr| enr.rlp_bytes().to_vec())
                .collect(),
        }
    }
}

impl TryFrom<NodesHelper> for Nodes {
    type Error = DecodeError;

    fn try_from(helper: NodesHelper) -> Result<Self, Self::Error> {
        let enrs: Vec<Enr> = helper
            .enrs
            .into_iter()
            .map(|bytes| {
                rlp::decode(&bytes)
                    .map_err(|e| DecodeError::BytesInvalid(format!("rlp decoding failed: {}", e)))
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            total: helper.total,
            enrs,
        })
    }
}

// TODO: check correctness and if there's a better way
// to impl Encode
impl ssz::Encode for Nodes {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        NodesHelper::from(self).ssz_append(buf)
    }
}

// TODO: check correctness and if there's a better way
// to impl Decode
impl ssz::Decode for Nodes {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        NodesHelper::from_ssz_bytes(bytes)?.try_into()
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct FindContent {
    // TODO: Use some version of H256
    pub content_key: Vec<u8>,
}


#[derive(Debug, PartialEq, Clone)]
pub struct FoundContent {
    pub enrs: Vec<SszEnr>,
    //// TODO: uncomment this after figuring out how to do ssz tuples
    pub payload: Vec<u8>,
}


#[derive(Debug, PartialEq, Clone)]
pub struct SszEnr(Enr);

impl SszEnr {
    pub fn new(enr: Enr) -> SszEnr {
        SszEnr(enr)
    }
}

impl Deref for SszEnr {
    type Target = Enr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SszEnr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ssz::Decode for SszEnr {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let string = match std::str::from_utf8(bytes) {
            Ok(val) => val,
            Err(e) => panic!("Invalid utf-8 sequence: {}", e),
        };
        // rlp decode?
        Ok(Self(Enr::from_str(string).unwrap()))
    }
}

impl ssz::Encode for SszEnr {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset = 8;
        let mut encoder = SszEncoder::container(buf, offset);
        println!("XXXX: {:?}", &self.rlp_bytes());
        encoder.append(&self.rlp_bytes().to_vec());
        encoder.finalize();
    }
}

impl ssz::Encode for FoundContent {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset = <Vec<SszEnr> as Encode>::ssz_fixed_len()
            + <Vec<u8> as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        match &self.enrs.len() {
            0 => {
                encoder.append(&self.enrs);
                encoder.append(&self.payload);
            },
            _ => {
                self.enrs.clone().into_iter().for_each(|enr| encoder.append(&enr));
                let empty: Vec<u8> = vec![];
                encoder.append(&empty);
            },
        }
        encoder.finalize();
    }
}

impl ssz::Decode for FoundContent {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);

        builder.register_type::<Vec<SszEnr>>()?;
        builder.register_type::<Vec<u8>>()?;

        let mut decoder = builder.build()?;
        Ok(Self {
            enrs: decoder.decode_next()?,
            payload: decoder.decode_next()?,
        })
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_found_content_encode_empty() {
        let empty_enrs: Vec<SszEnr> = vec![];
        let empty_payload: Vec<u8> = vec![];
        let msg = FoundContent{ enrs: empty_enrs, payload: empty_payload };
        let actual = msg.as_ssz_bytes();
        let decoded = FoundContent::from_ssz_bytes(&actual).unwrap();
        let empty_enrs_2: Vec<SszEnr> = vec![];
        let empty_payload_2: Vec<u8> = vec![];
        assert_eq!(decoded, msg);
        assert_eq!(decoded.enrs, empty_enrs_2);
        assert_eq!(decoded.payload, empty_payload_2);
    }

    #[test]
    fn test_found_content_encode_payload() {
        let empty_enrs: Vec<SszEnr> = vec![];
        let msg = FoundContent{ enrs: empty_enrs, payload: vec![1; 32] };
        let actual = msg.as_ssz_bytes();
        let decoded = FoundContent::from_ssz_bytes(&actual).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.payload, vec![1; 32]);
    }

    #[test]
    fn test_found_content_encode_single_enr() {
        let enr_key = CombinedKey::generate_secp256k1();
        let ip = Ipv4Addr::new(192,168,0,1);
        let enr = EnrBuilder::new("v4").ip(ip.into()).tcp(8000).build(&enr_key).unwrap();
        let enr_clone = enr.clone();
        let empty_payload: Vec<u8> = vec![];
        let msg = FoundContent{ enrs: vec![SszEnr(enr)], payload: empty_payload };
        let actual = msg.as_ssz_bytes();
        let decoded = FoundContent::from_ssz_bytes(&actual).unwrap();
        assert!(SszEnr(enr_clone).eq(decoded.enrs.first().unwrap()));
    }
}

use alloy::primitives::B256;
use ethportal_api::types::execution::{
    header::{Header, TxHashes},
    header_with_proof_new::BlockHeaderProof,
    transaction::Transaction,
    withdrawal::Withdrawal,
};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// Helper type to deserialize a response from a batched Header request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullHeaderBatch {
    pub headers: Vec<FullHeader>,
}

impl<'de> Deserialize<'de> for FullHeaderBatch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let obj: Vec<Value> = Deserialize::deserialize(deserializer)?;
        let results: Result<Vec<FullHeader>, _> = obj
            .into_iter()
            .map(|mut val| {
                let result = val["result"].take();
                FullHeader::try_from(result)
            })
            .collect();
        Ok(Self {
            headers: results.map_err(serde::de::Error::custom)?,
        })
    }
}

/// Datatype for use in bridge functionality. The purpose is a single datatype that can be created
/// from a header and contains all the information necessary to build history network content
/// values for BlockBodies (txs, uncles) and Receipts (tx_hashes) through subsequent jsonrpc
/// requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullHeader {
    pub header: Header,
    pub proof: Option<BlockHeaderProof>,
    pub txs: Vec<Transaction>,
    pub tx_hashes: TxHashes,
    pub uncles: Vec<B256>,
    pub withdrawals: Option<Vec<Withdrawal>>,
}

// Prefer TryFrom<Value> over implementing Deserialize trait, since it's much simpler when
// deserialize multiple types from a single json object.
impl TryFrom<Value> for FullHeader {
    type Error = anyhow::Error;

    fn try_from(val: Value) -> anyhow::Result<Self> {
        let header: Header = serde_json::from_value(val.clone())?;
        let uncles: Vec<B256> = serde_json::from_value(val["uncles"].clone())?;
        let tx_hashes: TxHashes = serde_json::from_value(val["transactions"].clone())?;
        let txs: Vec<Transaction> = serde_json::from_value(val["transactions"].clone())?;
        let withdrawals = match val["withdrawals"].clone() {
            Value::Null => None,
            _ => serde_json::from_value(val["withdrawals"].clone())?,
        };
        Ok(Self {
            header,
            proof: None,
            txs,
            tx_hashes,
            uncles,
            withdrawals,
        })
    }
}

impl FullHeader {
    pub fn validate(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ethportal_api::types::execution::block_body::{
        BlockBody, BlockBodyLegacy, BlockBodyShanghai,
    };
    use serde_json::Value;
    use ssz::{Decode, Encode};

    use super::*;

    #[test]
    fn full_header_from_get_block_response() {
        let body =
            std::fs::read_to_string("../../test_assets/mainnet/block_14764013_value.json").unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        let full_header = FullHeader::try_from(body["result"].clone()).unwrap();
        let header: Header = serde_json::from_value(body["result"].clone()).unwrap();
        assert_eq!(full_header.txs.len(), 19);
        assert_eq!(full_header.tx_hashes.hashes.len(), 19);
        assert_eq!(full_header.uncles.len(), 1);
        assert_eq!(full_header.header, header);
    }

    #[test]
    fn full_header_with_withdrawals() {
        let body =
            std::fs::read_to_string("../../test_assets/mainnet/block_17034871_value.json").unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        let full_header = FullHeader::try_from(body["result"].clone()).unwrap();
        let block_body = BlockBody::Shanghai(BlockBodyShanghai {
            txs: full_header.txs.clone(),
            withdrawals: full_header.withdrawals.unwrap(),
        });
        let header: Header = serde_json::from_value(body["result"].clone()).unwrap();
        block_body.validate_against_header(&header).unwrap();
    }

    #[test]
    fn full_header_with_empty_withdrawals() {
        let body =
            std::fs::read_to_string("../../test_assets/mainnet/block_17034873_value.json").unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        let full_header = FullHeader::try_from(body["result"].clone()).unwrap();
        let block_body = BlockBody::Shanghai(BlockBodyShanghai {
            txs: full_header.txs.clone(),
            withdrawals: full_header.withdrawals.unwrap(),
        });
        let header: Header = serde_json::from_value(body["result"].clone()).unwrap();
        block_body.validate_against_header(&header).unwrap();
    }

    #[rstest::rstest]
    // without blob txs
    #[case("19433902")]
    // with blob txs
    #[case("19433903")]
    fn full_header_block_body_dencun(#[case] case: &str) {
        let body =
            std::fs::read_to_string(format!("../../test_assets/mainnet/block_{case}_value.json"))
                .unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        let full_header = FullHeader::try_from(body["result"].clone()).unwrap();
        let header: Header = serde_json::from_value(body["result"].clone()).unwrap();
        let block_body = BlockBody::Shanghai(BlockBodyShanghai {
            txs: full_header.txs.clone(),
            withdrawals: full_header.withdrawals.unwrap(),
        });
        block_body.validate_against_header(&header).unwrap();
        // test ssz roundtrip
        let ssz = block_body.as_ssz_bytes();
        let decoded_block_body = BlockBody::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(block_body, decoded_block_body);
    }

    #[test_log::test]
    fn full_header_batch() {
        // this block (15573637) was chosen since it contains all tx types (legacy, access list,
        // eip1559) as well as contract creation txs
        let expected: String =
            std::fs::read_to_string("../../test_assets/geth_batch/headers.json").unwrap();
        let full_headers: FullHeaderBatch = serde_json::from_str(&expected).unwrap();
        for full_header in full_headers.headers {
            let block_body = BlockBody::Legacy(BlockBodyLegacy {
                txs: full_header.txs,
                uncles: vec![],
            });
            // test that txs are properly deserialized if tx root is properly calculated
            assert_eq!(
                block_body.transactions_root().unwrap(),
                full_header.header.transactions_root
            );
            // this block has no uncles, aka an empty uncles root is calculated.
            // there's no need to validate deserialization of uncles, since they're just a
            // vector of Header, which are already tested above
            assert_eq!(block_body.uncles_root(), full_header.header.uncles_hash);
        }
    }
}

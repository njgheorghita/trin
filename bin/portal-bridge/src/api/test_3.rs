#[cfg(test)]
mod test {
    use crate::api::consensus::ConsensusApi;
    use crate::api::execution::ExecutionApi;
    use crate::{DEFAULT_BASE_CL_ENDPOINT, DEFAULT_BASE_EL_ENDPOINT};
    use alloy::hex::FromHex;
    use alloy::primitives::B256;
    use e2store::era::Era;
    use ethportal_api::types::consensus::beacon_state::HistoricalBatch;
    use ethportal_api::OverlayContentKey;
    use ethportal_api::types::content_key::history::{HistoryContentKey, BlockHeaderByHashKey};
    use ethportal_api::types::content_value::history_new::HistoryContentValue;
    use ethportal_api::types::content_value::ContentValue;
    use ethportal_api::types::execution::header_with_proof_new::{BlockHeaderProof, BlockProofHistoricalRoots, HeaderWithProof, BeaconBlockProofHistoricalRoots, ExecutionBlockProofCapella, ExecutionBlockProof, BlockProofHistoricalSummaries, BeaconBlockProofHistoricalSummaries};
    use ethportal_api::utils::bytes::hex_encode;
    use reqwest::{header::HeaderMap, header::HeaderValue, header::CONTENT_TYPE, Client};
    use ssz_types::{typenum, FixedVector};
    use tree_hash::TreeHash;
    use trin_validation::historical_roots_acc::HistoricalRootsAccumulator;
    use trin_validation::merkle::proof::MerkleTree;
    use url::Url;
    use serde_yaml::Value;
    use serde::Deserialize;

    #[rstest::rstest]
    #[case(15539558, "cdf9ed89b0c43cda17398dc4da9cfc505e5ccd19f7c39e3b43474180f1051e01")]
    #[case(15547621, "96a9313cd506e32893d46c82358569ad242bb32786bd5487833e0f77767aec2a")]
    #[case(15555729, "c6fd396d54f61c6d0f1dd3653f81267b0378e9a0d638a229b24586d8fd0bc499")]
    #[tokio::test]
    async fn xxx_bellatrix(#[case] block_number: u64, #[case] hash: &str) {
        // deserialize yaml from file
        let test_vector = std::fs::read_to_string(format!("../../portal-spec-tests/tests/mainnet/history/headers_with_proof/block_proofs_bellatrix/beacon_block_proof-{}-{}.yaml", block_number, hash)).unwrap();
        let test_vector: Value = serde_yaml::from_str(&test_vector).unwrap();
        let v = test_vector.clone();
        let v = v.get("historical_roots_proof").unwrap();
        let beacon_block_proof: BeaconBlockProofHistoricalRoots = serde_yaml::from_value(v.clone()).unwrap();
        let beacon_block_root: &str = test_vector.get("beacon_block_root").unwrap().as_str().unwrap();
        let beacon_block_root: B256 = B256::from_hex(beacon_block_root).unwrap();
        let v = test_vector.clone();
        let v = v.get("beacon_block_proof").unwrap();
        let execution_block_proof: ExecutionBlockProof = serde_yaml::from_value(v.clone()).unwrap();
        let slot: u64 = test_vector.get("slot").unwrap().as_u64().unwrap();
        let proof = BlockProofHistoricalRoots {
            beacon_block_proof,
            beacon_block_root,
            execution_block_proof,
            slot,
        };

        // get header
        let url = Url::parse(DEFAULT_BASE_EL_ENDPOINT).unwrap();
        let execution_api = ExecutionApi::new(url.clone(), url, 10).await.unwrap();
        let header = execution_api.get_header(block_number, None).await.unwrap();

        // make hwp
        let hwp = HeaderWithProof {
            header: header.0.header,
            proof: BlockHeaderProof::HistoricalRoots(proof),
        };

        let content_key = HistoryContentKey::BlockHeaderByHash(BlockHeaderByHashKey {
            block_hash: hwp.header.hash().into(),
        });
        let content_value = HistoryContentValue::BlockHeaderWithProof(hwp.clone());
        println!("bellatrix : {:?}", block_number);
        println!("encoded content_key: {}", content_key.to_hex());
        println!("encoded content_value: {}", hex_encode(&content_value.encode()));
        println!("----");
        assert!(false);
    }

    #[rstest::rstest]
    #[case(17034870)]
    #[case(17042287)]
    #[case(17062257)]
    #[tokio::test]
    async fn xxx_bellatrix_capella(#[case] block_number: u64) {
        // deserialize yaml from file
        let test_vector = std::fs::read_to_string(format!("../../portal-spec-tests/tests/mainnet/history/headers_with_proof/block_proofs_capella/beacon_block_proof-{}.yaml", block_number)).unwrap();
        let test_vector: Value = serde_yaml::from_str(&test_vector).unwrap();
        let v = test_vector.clone();
        let v = v.get("historical_summaries_proof").unwrap();
        let beacon_block_proof: BeaconBlockProofHistoricalSummaries = serde_yaml::from_value(v.clone()).unwrap();
        let beacon_block_root: &str = test_vector.get("beacon_block_root").unwrap().as_str().unwrap();
        let beacon_block_root: B256 = B256::from_hex(beacon_block_root).unwrap();
        let v = test_vector.clone();
        let v = v.get("beacon_block_proof").unwrap();
        let execution_block_proof: ExecutionBlockProofCapella = serde_yaml::from_value(v.clone()).unwrap();
        let slot: u64 = test_vector.get("slot").unwrap().as_u64().unwrap();
        let proof = BlockProofHistoricalSummaries {
            beacon_block_proof,
            beacon_block_root,
            execution_block_proof,
            slot,
        };

        // get header
        let url = Url::parse(DEFAULT_BASE_EL_ENDPOINT).unwrap();
        let execution_api = ExecutionApi::new(url.clone(), url, 10).await.unwrap();
        let header = execution_api.get_header(block_number, None).await.unwrap();

        // make hwp
        let hwp = HeaderWithProof {
            header: header.0.header,
            proof: BlockHeaderProof::HistoricalSummaries(proof),
        };

        let content_key = HistoryContentKey::BlockHeaderByHash(BlockHeaderByHashKey {
            block_hash: hwp.header.hash().into(),
        });
        let content_value = HistoryContentValue::BlockHeaderWithProof(hwp.clone());
        println!("capella : {:?}", block_number);
        println!("encoded content_key: {}", content_key.to_hex());
        println!("encoded content_value: {}", hex_encode(&content_value.encode()));
        println!("----");
        assert!(false);
    }
}

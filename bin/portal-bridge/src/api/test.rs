#[cfg(test)]
mod test {
    use alloy::hex::FromHex;
    use tree_hash::TreeHash;
    use alloy::primitives::B256;
    use ssz_types::{typenum, FixedVector};
    use crate::api::consensus::ConsensusApi;
    use crate::api::execution::ExecutionApi;
    use trin_validation::merkle::proof::MerkleTree;
    use crate::{DEFAULT_BASE_CL_ENDPOINT, DEFAULT_BASE_EL_ENDPOINT};
    use ethportal_api::types::execution::header_with_proof_new::{HeaderWithProof, BlockProofHistoricalRoots, BlockHeaderProof};
    use trin_validation::historical_roots_acc::HistoricalRootsAccumulator;
    use url::Url;
    use ethportal_api::utils::bytes::{hex_encode, hex_decode};
    use ethportal_api::types::consensus::beacon_state::HistoricalBatch;
    use ethportal_api::types::consensus::beacon_block::BeaconBlockBellatrix;
    use e2store::era::Era;
    use reqwest::{Client, header::HeaderMap, header::HeaderValue, header::CONTENT_TYPE};
    use ethportal_api::types::execution::header_with_proof::{HeaderWithProof as HeaderWithProofOld, BlockHeaderProof as BlockHeaderProofOld};
    use ethportal_api::types::content_value::history::{HistoryContentValue as HistoryContentValueOld};
    use ethportal_api::types::content_value::history_new::HistoryContentValue;
    use ethportal_api::{HistoryContentKey, OverlayContentKey, ContentValue};

    // 15_555_729
    fn expected_proof() -> BlockProofHistoricalRoots {
        let execution_block_proof: FixedVector<B256, typenum::U11> = FixedVector::from([
            B256::from_hex("0x494e7fa99777791f708752d986c8f819afab429d533d0990862b039d74c16334").unwrap(),
            B256::from_hex("0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b").unwrap(),
            B256::from_hex("0x8c9e2376454618be2a49208834acbef8efad91fd63e120709836239cf3f3965e").unwrap(),
            B256::from_hex("0xeada8ab88e38c0314453ba83a19d16cf9d7ac1c68995fd8b9b54a58f2384a956").unwrap(),
            B256::from_hex("0x6e9a918b7435624d2dcf95503727499a3d17b5ecc522cf3ab017403b75461937").unwrap(),
            B256::from_hex("0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b").unwrap(),
            B256::from_hex("0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71").unwrap(),
            B256::from_hex("0xe40d513acb66b3698df13a593c6d317a9ff0ce1607d6d0c92e4a00ac71f3a5e5").unwrap(),
            B256::from_hex("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            B256::from_hex("0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b").unwrap(),
            B256::from_hex("0xa4427b1b8a34052b81657fb0c2e2602c34102da7434dd67728aabc9bdd142d16").unwrap(),
        ].to_vec());
        let beacon_block_root = B256::from_hex("0xe3040c0b5bbcb4f53d4a9d2cb2eeb1ba72eeaf54005e15e387af5829bf786032").unwrap();
        let beacon_block_proof: FixedVector<B256, typenum::U14> = FixedVector::from([
          B256::from_hex("0x314e9ca9396abb0898ce009c85990359a45c18a97f254f99c79b11e66ed1699b").unwrap(),
          B256::from_hex("0xe5f76565433dfdb5f2ef643ccf6b93efc00dfa6cc57610022534f4ae3b0f49fb").unwrap(),
          B256::from_hex("0x7f1917c2db12556ab98cd41d5a7c5ed8aa64be1cb691fc7eca503006ca89c464").unwrap(),
          B256::from_hex("0xde74802f27625c42a249879f9bfbdf8c189b56ac1a273d334d9e7979a7a18653").unwrap(),
          B256::from_hex("0x6d950fb57fde8a2e302a5709128608c071ddce2cd1b3d72b38f510d4ec438f3d").unwrap(),
          B256::from_hex("0xd6b9fd163d53ab6518f2e46e6e5a2d79f1b2f5311f00a0639208dc496fc09762").unwrap(),
          B256::from_hex("0xa2592811e61072d442c6874c0c9eb4796f18b9b6590e7da10ce5f580f8e05c0f").unwrap(),
          B256::from_hex("0x7ef76e3386e5dd2c597f8777c407496e3eb9fa461fb5436aefef5c8a17e940a0").unwrap(),
          B256::from_hex("0xd17dadb989c4d5eeb0f8144006355dee7e517589f3201794861f38f2a5a2cb3a").unwrap(),
          B256::from_hex("0xd693dc8c431a95dac6f4b1ef27f2c9de0aa3543315665cca21a4dfa13136c071").unwrap(),
          B256::from_hex("0xa5c35f8522ef3e816506ac326be3c1828ecdcbb93ef8d2cb668091f8dac5c49b").unwrap(),
          B256::from_hex("0x28abd907b5e7cdc6e1d760b8fbe63d7e68550335f84e8119e7435f2e5948fe6e").unwrap(),
          B256::from_hex("0x1bec32ad4488d3a4d17dacb3a5e2c670db161f1abcf61777aeb18ed5952fe597").unwrap(),
          B256::from_hex("0xff2fa8b781b49404b97cc07985c467c1208d96094e2494cbd787be6029590c3a").unwrap(),
        ].to_vec());
        let slot = 4718592;
        BlockProofHistoricalRoots {
            beacon_block_proof,
            beacon_block_root,
            execution_block_proof,
            slot,
        }
    }

    // era files on the borders are not working...
    // eg. 575.era is not working
    #[tokio::test]
    async fn test_xxxy() {
        let raw_era = std::fs::read("../../test_assets/era1/m577.era").unwrap();

        let era_state = Era::deserialize_to_beacon_state(&raw_era.clone()).unwrap();
        let historical_batch = HistoricalBatch {
            state_roots: era_state.state_roots().clone().into(),
            block_roots: era_state.block_roots().clone().into(),
        };

        let hb_proof = historical_batch.build_block_root_proof(0);

        let mut block = Era::iter_blocks(raw_era.clone()).unwrap();
        let beacon_block = block.nth(0).unwrap();
        let beacon_block = beacon_block.unwrap();
        let beacon_block = beacon_block.block.message_merge().unwrap();
        assert_eq!(beacon_block.slot, 4_718_592);

        // beacon block proof
        let beacon_block_hash = beacon_block.tree_hash_root();

        // execution block proof
        let mut execution_block_hash_proof = beacon_block.body.build_execution_block_hash_proof();
        let body_root_proof = beacon_block.build_body_root_proof();
        execution_block_hash_proof.extend(body_root_proof);
        let execution_block_proof: FixedVector<B256, typenum::U11> = execution_block_hash_proof.into();
        let beacon_block_proof: FixedVector<B256, typenum::U14> = hb_proof.into();

        let proof = BlockProofHistoricalRoots {
            beacon_block_proof,
            beacon_block_root: beacon_block_hash,
            slot: beacon_block.slot,
            execution_block_proof,
        };


        let actual_proof = expected_proof();
        assert_eq!(actual_proof.slot, proof.slot);
        assert_eq!(actual_proof.beacon_block_root, proof.beacon_block_root);
        assert_eq!(actual_proof.execution_block_proof, proof.execution_block_proof);
        assert_eq!(actual_proof.beacon_block_proof, proof.beacon_block_proof);
    }

    #[tokio::test]
    async fn test_xpmv() {
        let (ck, cv) = vector();
        let ck = hex_decode(&ck).unwrap();
        let cv = hex_decode(&cv).unwrap();
        let ck = HistoryContentKey::try_from_bytes(&ck).unwrap();
        let old_hwp = HistoryContentValueOld::decode(&ck, &cv).unwrap();
        let header = match old_hwp {
            HistoryContentValueOld::BlockHeaderWithProof(hwp) => hwp.header,
            _ => panic!("unexpected content value"),
        };

        let raw_era = std::fs::read("../../test_assets/era1/m582.era").unwrap();
        let era_state = Era::deserialize_to_beacon_state(&raw_era.clone()).unwrap();
        let historical_batch = HistoricalBatch {
            state_roots: era_state.state_roots().clone().into(),
            block_roots: era_state.block_roots().clone().into(),
        };

        // 15_600_000
        let slot = 4_763_310;
        let slot_index = slot % 8192;
        let hb_proof = historical_batch.build_block_root_proof(slot_index);

        let mut beacon_block = None;
        for block in Era::iter_blocks(raw_era.clone()).unwrap() {
            let block = block.unwrap();
            let block = block.block.message_merge().unwrap();
            if block.slot == slot {
                beacon_block = Some(block.clone());
                break;
            }
        }
        let beacon_block = beacon_block.unwrap();
        assert_eq!(beacon_block.slot, slot);
        assert_eq!(beacon_block.body.execution_payload.block_number, 15_600_000);

        // beacon block proof
        let beacon_block_hash = beacon_block.tree_hash_root();

        // execution block proof
        let mut execution_block_hash_proof = beacon_block.body.build_execution_block_hash_proof();
        let body_root_proof = beacon_block.build_body_root_proof();
        execution_block_hash_proof.extend(body_root_proof);
        let execution_block_proof: FixedVector<B256, typenum::U11> = execution_block_hash_proof.into();
        let beacon_block_proof: FixedVector<B256, typenum::U14> = hb_proof.into();

        let proof = BlockProofHistoricalRoots {
            beacon_block_proof,
            beacon_block_root: beacon_block_hash,
            slot: beacon_block.slot,
            execution_block_proof,
        };

        let hwp = HeaderWithProof {
            header,
            proof: BlockHeaderProof::HistoricalRoots(proof),
        };
        let content_value = HistoryContentValue::BlockHeaderWithProof(hwp);
        let encoded = content_value.encode();

        println!("encoded: {}", hex_encode(&encoded));
        assert!(false);
        //let actual_proof = expected_proof();
        //assert_eq!(actual_proof.slot, proof.slot);
        //assert_eq!(actual_proof.beacon_block_root, proof.beacon_block_root);
        //assert_eq!(actual_proof.execution_block_proof, proof.execution_block_proof);
        //assert_eq!(actual_proof.beacon_block_proof, proof.beacon_block_proof);
    }

    fn vector() -> (String, String)  {
        (
            "0x0066a402a69b896a9152fe2164b7aa083f7ae9029e9e0694c9b5ece48176db592d".to_string(),
            "0x080000000c020000f90201a0f27cf46c7051211f7dc78a3e837b84afc52a3d17397ff7f3d45cb325d7bfc452a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794388c818ca8b9251b393131c08a736a67ccb19297a0d6389937b3f9b463a5a6ea4a404eca63cb53c625e7a2768f1ec1c232295adc50a0a3d66862764ad81dd1384712247f53e171ecd40553328e722d3a627494b678c8a0c5f1cc46e949ce9a6607f1ffb4018b0a893e071e9fd63123d9e8f3647f74d99bb901005920c0e4011a3db1367828408091036a7c2830229442428128d5321ed4d213621584ca0422a290480846eef83203558c07a840541a0136c044720b2e64b7a2c040802208530e053a6d05451c074bc170009102f10ed4100322a234419ac03120422b18498a27c2ba3420219184301f50441b0c5a19260cf06036467cce8b0dc4183105225a3fb04a3acb644a46a320200cc282c18bf55078022502c8427839809ac019eb0022e4f21ca14085071990809345808b21462a8b06242b2e4ccc11c96f5e5d87240134801c4801428a2cc854202008cd9088a0b665661f6f3c10b25ef61d24a8042006480408dca20787385401188164c0aca14221462808eb3070568083ee09808401c9c3808383c6d984632e607f80a0fab4b7eb057ad749b436c2bd93321ecd6bc7ad58d12e5ac72e7e20b1f55e96c388000000000000000085018422588900".to_string()
        )
    }
}

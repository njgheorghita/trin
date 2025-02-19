#[cfg(test)]
mod test {
    use alloy::hex::FromHex;
    use tree_hash::TreeHash;
    use alloy::primitives::B256;
    use ssz_types::{typenum, FixedVector, VariableList};
    use ssz::Decode;
    use crate::api::consensus::ConsensusApi;
    use crate::api::execution::ExecutionApi;
    use trin_validation::merkle::proof::MerkleTree;
    use crate::{DEFAULT_BASE_CL_ENDPOINT, DEFAULT_BASE_EL_ENDPOINT};
    use ethportal_api::types::execution::header_with_proof_new::{BlockProofHistoricalRoots, BlockProofHistoricalSummaries};
    use trin_validation::historical_roots_acc::HistoricalRootsAccumulator;
    use url::Url;
    use ethportal_api::utils::bytes::hex_encode;
    use ethportal_api::types::consensus::beacon_state::{HistoricalBatch, BeaconStateCapella};
    use ethportal_api::types::consensus::historical_summaries::{HistoricalSummaries, HistoricalSummary};
    use ethportal_api::types::consensus::beacon_block::BeaconBlockBellatrix;
    use e2store::era::Era;
    use reqwest::{Client, header::HeaderMap, header::HeaderValue, header::CONTENT_TYPE};

    // 17_062_257
    fn expected_proof() -> BlockProofHistoricalSummaries {
        let execution_block_proof: VariableList<B256, typenum::U12> = VariableList::from([
          B256::from_hex("0xee31d5895816b404e36e5934a5b457b80c79d86ffdff727281c4349669ecefd2").unwrap(),
          B256::from_hex("0xedb4b325350d65ff5ccd18296701e3552271c62db20554153f4ebd98af10d162").unwrap(),
          B256::from_hex("0x00e4e1d2eff05d313050e03c9af742dc714bfa30b360a8e6919c35b269dac0fa").unwrap(),
          B256::from_hex("0xea898076d90a15f449bd3e88d7a1252a354646e32f5adfe8d3000cc063203d4c").unwrap(),
          B256::from_hex("0x5c27d6ab6527347cc63dbde78e0129636fd891d65668a058b71622c31fc0c17f").unwrap(),
          B256::from_hex("0x336488033fe5f3ef4ccc12af07b9370b92e553e35ecb4a337a1b1c0e4afe1e0e").unwrap(),
          B256::from_hex("0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71").unwrap(),
          B256::from_hex("0x6fa54e441e9b4d64d8a58ccde30ebad4caacbd9a769eb0c15c2bfcb2da8dc098").unwrap(),
          B256::from_hex("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
          B256::from_hex("0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b").unwrap(),
          B256::from_hex("0x90f2a3dbc09f6f7a539b371651a195fe72bdcf4019ee12681065945a676e2799").unwrap(),
        ].to_vec());
        let beacon_block_root = B256::from_hex("0x228a343bc2ffed918ee8dd619cc5d862486b197b25720de9d130e3347b5677a3").unwrap();
        let beacon_block_proof: FixedVector<B256, typenum::U13> = FixedVector::from([
            B256::from_hex("0x0e2f72947188d7e8e477f8de50e37dd09d61cd54483fe85951c65370a0391fdd").unwrap(),
            B256::from_hex("0x008a2b42b1a346a72444ecb9bd90782f819b4dbf8897e79e8a922778f18a7067").unwrap(),
            B256::from_hex("0x5d3b9c1eea77c1841db1bc1586092314b406c784def92aa8d501b4a703f34b41").unwrap(),
            B256::from_hex("0x29b0d629873b967018c25c882b5da204c29fe87829b9ca0e49348de5f6c5bba8").unwrap(),
            B256::from_hex("0xed5da680e34e964bd65547a983c486a66cff6aa1dec56cfedc7bb9337083866e").unwrap(),
            B256::from_hex("0xf8b9f0078482d6cdcd5a268ce2cd9a7505d19624622b19b8c5b96d6fab7c0311").unwrap(),
            B256::from_hex("0x124fedd81c197075da04153b6fde4fce2cb1abd8881942c6458359c54971bf5f").unwrap(),
            B256::from_hex("0x5b78e9349fb5d2ba78ba8fb3882c4ae31e513a4d66d8c8cd8ef4c9f2161ef2c3").unwrap(),
            B256::from_hex("0x84749bd3f3dad7b2e3ceedf2e882f6fdd29fc832b7aa678d811bfc980e022414").unwrap(),
            B256::from_hex("0xf991879c08522fbd9d3b6ee9eb731783819844d1716d40e9648b3eaacddf6603").unwrap(),
            B256::from_hex("0x8b09f415d2f7b09203ef095edb1dff1ffc5c0b6dc6fd48a3f014a7939591fd38").unwrap(),
            B256::from_hex("0xfb320e73c4f3819af90c748a49f066f182361e9a0773ac711d364524cbf570b2").unwrap(),
            B256::from_hex("0x8b5a434f375c577b7007a3ed199b36ed245304cd229058f852597a78d7d330de").unwrap(),
        ].to_vec());
        let slot = 6_238_210;
        BlockProofHistoricalSummaries {
            beacon_block_proof,
            beacon_block_root,
            execution_block_proof,
            slot,
        }
    }

    // era files on the borders are not working...
    // eg. 575.era is not working
    #[tokio::test]
    async fn test_xxyy() {
        let raw_era = std::fs::read("../../test_assets/era1/m762.era").unwrap();

        let era_state = Era::deserialize_to_beacon_state(&raw_era.clone()).unwrap();
        /*println!("deserialized era state");*/
        /*let mut historical_summaries = vec![];*/
        /*let summaries = era_state.historical_summaries().unwrap();*/
        /*println!("len of summaries: {}", summaries.len());*/
        /*for (i, summary) in summaries.iter().enumerate() {*/
            /*println!("index: {}", i);*/
            /*historical_summaries.push(summary);*/
        /*}*/
        /*println!("done with historical summaries");*/

        let slot = 6_238_210;
        let slot_index = 4003;
        let beacon_block = Era::iter_blocks(raw_era.clone()).unwrap().nth(slot_index).unwrap();
        let beacon_block = beacon_block.unwrap();
        let beacon_block = beacon_block.block.message_capella().unwrap();
        assert_eq!(beacon_block.slot, slot);
        
        // execution block proof
        let mut execution_block_hash_proof = beacon_block.body.build_execution_block_hash_proof();
        println!("execution block hash proof: {:?}", execution_block_hash_proof);
        let body_root_proof = beacon_block.build_body_root_proof();
        println!("body root proof: {:?}", body_root_proof);
        execution_block_hash_proof.extend(body_root_proof);
        let execution_block_proof: VariableList<B256, typenum::U12> = execution_block_hash_proof.into();

        // claude stuff, double check
        let capella_epoch = 758;
        let era_slot = 328;

        // beacon block proof
        //
        let raw_historical_summaries = std::fs::read("../../portal-spec-tests/tests/mainnet/history/headers_with_proof/block_proofs_capella/historical_summaries_at_slot_8953856.ssz").unwrap();
        let historical_summaries = HistoricalSummaries::from_ssz_bytes(&raw_historical_summaries).unwrap();
        println!("len of historical summaries: {}", historical_summaries.len());
        let historical_summary = historical_summaries.get(era_slot).unwrap();
        println!("historical summary: {:?}", historical_summary);

        let capella_state = era_state.as_capella().unwrap();
        let proof = capella_state.build_historical_summaries_proof();

        let beacon_block_hash = beacon_block.tree_hash_root();
        println!("beacon block hash: {:?}", beacon_block_hash);

        assert!(capella_state.block_roots.contains(&beacon_block_hash));
        assert_eq!(capella_state.block_roots.iter().nth(slot as usize % 8192 as usize).unwrap().clone(), beacon_block_hash);
        println!("XXX asserteed");
        println!("slot index: {}", slot % 8192);

        let block_root_proof = capella_state.build_block_root_proof(slot % 8192);
        println!("block root proof: {:?}", block_root_proof);

        let beacon_block_proof: FixedVector<B256, typenum::U13> = block_root_proof.into();
        //let execution_block_proof: VariableList<B256, typenum::U12> = block_root_proof.into();

        let proof = BlockProofHistoricalSummaries {
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
}

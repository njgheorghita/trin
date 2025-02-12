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
    use ethportal_api::types::execution::header_with_proof_new::BlockProofHistoricalRoots;
    use trin_validation::historical_roots_acc::HistoricalRootsAccumulator;
    use url::Url;
    use ethportal_api::utils::bytes::hex_encode;
    use ethportal_api::types::consensus::beacon_state::HistoricalBatch;
    use ethportal_api::types::consensus::beacon_block::BeaconBlockBellatrix;
    use e2store::era::Era;
    use reqwest::{Client, header::HeaderMap, header::HeaderValue, header::CONTENT_TYPE};

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

    /*fn expected_proof_2() -> BlockProofHistoricalRoots {*/
        /*let execution_block_proof: FixedVector<B256, typenum::U11> = FixedVector::from([*/
            /*B256::from_hex("0x494e7fa99777791f708752d986c8f819afab429d533d0990862b039d74c16334").unwrap(),*/
            /*B256::from_hex("0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b").unwrap(),*/
            /*B256::from_hex("0x8c9e2376454618be2a49208834acbef8efad91fd63e120709836239cf3f3965e").unwrap(),*/
            /*B256::from_hex("0xeada8ab88e38c0314453ba83a19d16cf9d7ac1c68995fd8b9b54a58f2384a956").unwrap(),*/
            /*B256::from_hex("0x6e9a918b7435624d2dcf95503727499a3d17b5ecc522cf3ab017403b75461937").unwrap(),*/
            /*B256::from_hex("0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b").unwrap(),*/
            /*B256::from_hex("0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71").unwrap(),*/
            /*B256::from_hex("0xe40d513acb66b3698df13a593c6d317a9ff0ce1607d6d0c92e4a00ac71f3a5e5").unwrap(),*/
            /*B256::from_hex("0x").unwrap(),*/
        /*]);*/
        /*Ok(())*/
    /*}*/

    // era files on the borders are not working...
    // eg. 575.era is not working
    #[tokio::test]
    async fn test_xxxy() {
        let raw_era = std::fs::read("../../test_assets/era1/m577.era").unwrap();
/*        let mut beacon_block = None;*/
        /*let mut iter = Era::iter_blocks(raw_era.clone()).unwrap();*/
        /*while let Some(block) = iter.next() {*/
            /*let block = block.unwrap();*/
            /*if block.block.slot() == 4_718_592 {*/
                /*beacon_block = Some(block);*/
                /*println!("found block.slot(): {:?}", 4_718_592);*/
                /*break;*/
            /*} else {*/
                /*println!("block.slot(): {:?}", block.block.slot());*/
            /*}*/
        /*}*/
        /*let beacon_block = beacon_block.unwrap();*/
        /*let block_number = beacon_block.block.execution_block_number();*/
        /*let beacon_block = beacon_block.block.message_merge().unwrap();*/


        /*let mut leaves = Vec::new();*/
        /*let mut i = 0u64;*/
        /*for block in Era::iter_blocks(raw_era.clone()).unwrap() {*/
            /*let block = block.unwrap();*/
            /*let block = block.block.message_merge().unwrap();*/
            /*let block_index = block.slot % 8192;*/
            /*println!("----- i: {:?} - block_index: {:?}", i, block_index);*/
            
            /*while i < block_index {*/
                /*println!("missing block.slot: {:?}", i);*/
                /*leaves.push(B256::default());*/
                /*i += 1;*/
            /*}*/

            /*println!("pushing block.slot: {:?}", block_index);*/
            /*leaves.push(block.tree_hash_root());*/
            /*i += 1;*/
            
            /*if i == 8192 {*/
                /*break;*/
            /*}*/
        /*}*/

        /*// Fill in any remaining slots with defaults*/
        /*while i < 8192 {*/
            /*println!("missing final block.slot: {:?}", i);*/
            /*leaves.push(B256::default());*/
            /*i += 1;*/
        /*}*/
        

        let era_state = Era::deserialize_to_beacon_state(&raw_era.clone()).unwrap();
        // The state.state_roots should contain all state roots for this period
        // You'll want to collect these similar to how you're collecting block roots
        println!("state length: {:?}", era_state.state_roots().len());
        let historical_batch = HistoricalBatch {
            state_roots: era_state.state_roots().clone().into(),
            block_roots: era_state.block_roots().clone().into(),
        };

        let historical_batch_root = historical_batch.tree_hash_root();
        println!("historical_batch_root: {:?}", hex_encode(historical_batch_root));

        let hb_proof = historical_batch.build_block_root_proof(0);
        println!("hb_proof: {:?}", hb_proof);
        println!("---");

        //let merkle_tree = MerkleTree::create(&leaves, 13);
        //let merkle_tree_root = merkle_tree.hash();
        //println!("merkle_tree_root: {:?}", hex_encode(merkle_tree_root));
        
        let mut block = Era::iter_blocks(raw_era.clone()).unwrap();
        let beacon_block = block.nth(0).unwrap();
        let beacon_block = beacon_block.unwrap();
        let beacon_block = beacon_block.block.message_merge().unwrap();
        assert_eq!(beacon_block.slot, 4_718_592);

        // get historical roots lea
        let historical_roots_acc = HistoricalRootsAccumulator::default();
        let root_index = beacon_block.slot / 8192;
        let historical_roots_leaf = historical_roots_acc.historical_roots[root_index as usize];
        println!("historical_roots_leaf: {:?}", hex_encode(historical_roots_leaf));

        let block_root_index = beacon_block.clone().slot % 8192;
        let gen_index = 2 * 8192 + block_root_index;

        // beacon block proof
        let beacon_block_hash = beacon_block.tree_hash_root();
        println!("beacon_block_hash: {:?}", hex_encode(beacon_block_hash));

        // execution block proof
        let execution_block_hash = beacon_block.body.execution_payload.block_hash;
        println!("proof: {:?}", hb_proof);
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

        /*let cl_endpoint = Url::parse(DEFAULT_BASE_CL_ENDPOINT).unwrap();*/
        /*let consensus_api =*/
            /*ConsensusApi::new(cl_endpoint.clone(), cl_endpoint, 10)*/
                /*.await*/
                /*.unwrap();*/

        /*// 16_000_000*/
        /*let (full_header, _, _, _) = execution_api.get_header(19_900_000, None).await.unwrap();*/
        /*//let execution_hash = "0xcc252ff074cb64ea38c6d7c1cf27dfe32deab31d2acf7b72a41ae1f6538800ca";*/
        /*//assert_eq!(hex_encode(full_header.header.hash()), execution_hash);*/
        /*let beacon_block_root = hex_encode(full_header.header.parent_beacon_block_root.unwrap());*/
        /*println!("beacon: {:?}", full_header.header.parent_beacon_block_root);*/

        /*let beacon_block = consensus_api.get_beacon_block(beacon_block_root).await.unwrap();*/
        /*assert_eq!(beacon_block, "xxx");*/
    }

    /*#[tokio::test]*/
    /*async fn test_yyy() {*/
        /*use ethportal_api::types::content_value::history_new::HistoryContentValue;*/
        /*use ethportal_api::types::execution::header_with_proof_new::{HeaderWithProof, BlockHeaderProof};*/
        /*use ssz::{Decode, Encode};*/


        /*let proof = expected_proof();*/
        /*let hwp = HeaderWithProof {*/
            /*header: (),*/
            /*proof: BlockHeaderProof::HistoricalRoots(proof.clone()),*/
        /*};*/
        /*let encoded = hex_encode(ssz::Encode::as_ssz_bytes(&hwp));*/
        /*println!("encoded: {:?}", hex_encode(encoded.clone()));*/

        /*let proof_2 = expected_proof_2();*/
        /*let hwp = HeaderWithProof {*/
            /*header: (),*/
            /*proof: BlockHeaderProof::HistoricalSummaries(proof_2.clone()),*/
        /*};*/
        /*let encoded = hex_encode(ssz::Encode::as_ssz_bytes(&hwp));*/
        /*println!("encoded: {:?}", hex_encode(encoded.clone()));*/
        /*assert!(false);*/
    /*}*/
}

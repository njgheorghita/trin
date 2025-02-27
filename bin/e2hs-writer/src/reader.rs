use std::{path::PathBuf, sync::Arc};

use alloy::primitives::B256;
use anyhow::anyhow;
use async_stream::stream;
use e2store::{
    era::Era,
    era1::Era1,
    utils::{get_era1_files, get_era_files},
};
use ethportal_api::types::{
    consensus::beacon_state::{HistoricalBatch, BeaconState},
    consensus::fork::ForkName,
    execution::{
        accumulator::EpochAccumulator,
        block_body::{BlockBody, BlockBodyMerge},
        header_with_proof_new::{
            BlockHeaderProof, BlockProofHistoricalHashesAccumulator, BlockProofHistoricalRoots,
            BlockProofHistoricalSummaries, HeaderWithProof,
        },
        receipts::Receipts,
    },
};
use futures::Stream;
use portal_bridge::{
    api::execution::ExecutionApi, bridge::utils::lookup_epoch_acc, DEFAULT_BASE_EL_ENDPOINT,
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use ssz::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};
use tree_hash::TreeHash;
use trin_execution::era::binary_search::EraBinarySearch;
use trin_validation::{accumulator::PreMergeAccumulator, header_validator::HeaderValidator};
use url::Url;

const ERA1_EPOCH: u64 = 1892;
const MERGE_BLOCK: u64 = 16_000_000;
const CAPELLA_BLOCK: u64 = 17_000_000;
const DENEB_BLOCK: u64 = 18_000_000;

pub struct EraProvider {
    raw_era1: Option<Vec<u8>>,
    first_era: Option<Arc<Era>>,
    second_era: Option<Arc<Era>>,
}

impl EraProvider {
    async fn new(epoch: u64) -> anyhow::Result<Self> {
        let starting_block = epoch * 8192;
        let ending_block = starting_block + 8192;
        let mut raw_era1 = None;
        let mut first_era = None;
        let mut second_era = None;
        let http_client = Client::builder()
            .default_headers(HeaderMap::from_iter([(
                CONTENT_TYPE,
                HeaderValue::from_static("application/xml"),
            )]))
            .build()?;
        if starting_block < MERGE_BLOCK {
            let era1_paths = get_era1_files(&http_client).await?;
            let era1_path = era1_paths.get(&starting_block).unwrap();
            raw_era1 = Some(
                http_client
                    .get(era1_path)
                    .send()
                    .await?
                    .bytes()
                    .await?
                    .to_vec(),
            );
        } else {
            let starting_era =
                EraBinarySearch::find_era_file(http_client.clone(), starting_block).await?;
            let ending_era =
                EraBinarySearch::find_era_file(http_client.clone(), ending_block).await?;

            let starting_epoch = starting_era.epoch_index;
            let ending_epoch = ending_era.epoch_index;

            let era_links = get_era_files(&http_client).await?;
            let starting_era_path = era_links.get(&starting_epoch).unwrap();
            let starting_era = http_client
                .get(starting_era_path)
                .send()
                .await?
                .bytes()
                .await?
                .to_vec();
            first_era = Some(Arc::new(Era::deserialize(&starting_era)?));
            if starting_epoch != ending_epoch {
                let ending_era_path = era_links.get(&ending_epoch).unwrap();
                let ending_era = http_client
                    .get(ending_era_path)
                    .send()
                    .await?
                    .bytes()
                    .await?
                    .to_vec();
                second_era = Some(Arc::new(Era::deserialize(&ending_era)?));
            }
        }
        Ok(Self {
            raw_era1,
            first_era,
            second_era,
        })
    }
}

pub struct AllBlockData {
    pub block: u64,
    pub header_with_proof: HeaderWithProof,
    pub body: BlockBody,
    pub receipts: Receipts,
}

pub struct EpochReader {
    epoch: u64,
    current_block: u64,
    ending_block: u64,
    epoch_accumulator: Option<Arc<EpochAccumulator>>,
    execution_api: ExecutionApi,
    era_provider: EraProvider,
}

impl EpochReader {
    pub async fn new(epoch: u64, epoch_acc_path: PathBuf) -> anyhow::Result<Self> {
        let starting_block = epoch * 8192;
        let ending_block = starting_block + 8192;
        let era_provider = EraProvider::new(starting_block).await?;
        let epoch_accumulator = match epoch <= ERA1_EPOCH {
            true => {
                let epoch_index = starting_block / 8192;
                let header_validator = HeaderValidator::new();
                Some(Arc::new(
                    lookup_epoch_acc(
                        epoch_index,
                        &header_validator.pre_merge_acc,
                        &epoch_acc_path,
                    )
                    .await?,
                ))
            }
            false => None,
        };
        let execution_api = ExecutionApi::new(
            Url::parse(DEFAULT_BASE_EL_ENDPOINT)?,
            Url::parse(DEFAULT_BASE_EL_ENDPOINT)?,
            10,
        )
        .await?;
        Ok(Self {
            epoch,
            current_block: starting_block, // Track the current block
            ending_block,
            epoch_accumulator,
            execution_api,
            era_provider,
        })
    }

    fn get_era_for_block_number(&self, block_number: u64) -> &Arc<Era> {
        if block_number < MERGE_BLOCK {
            panic!("logic is bad")
        }
        if let Some(first_era) = &self.era_provider.first_era {
            if first_era.contains(block_number) {
                return first_era;
            }
        }

        if let Some(second_era) = &self.era_provider.second_era {
            if second_era.contains(block_number) {
                return second_era;
            }
        }
        panic!("logic is bad")
    }

    fn get_pre_merge_block_data(&self, block_number: u64) -> anyhow::Result<AllBlockData> {
        let raw_era1 = self.era_provider.raw_era1.clone().unwrap();
        let block_index = block_number % 8192;
        let tuple = Era1::get_tuple_by_index(&raw_era1, block_index);
        let header = tuple.header.header;
        let receipts = tuple.receipts.receipts;
        let body = tuple.body.body;
        let proof =
            PreMergeAccumulator::construct_proof(&header, &self.epoch_accumulator.clone().unwrap())
                .unwrap();
        let proof = BlockProofHistoricalHashesAccumulator::new(proof.proof.clone().into()).unwrap();
        let header_with_proof = HeaderWithProof {
            header,
            proof: BlockHeaderProof::HistoricalHashes(proof),
        };
        Ok(AllBlockData {
            block: block_number,
            header_with_proof,
            body,
            receipts,
        })
    }

    async fn get_pre_capella_block_data(&self, block_number: u64) -> anyhow::Result<AllBlockData> {
        let era = self.get_era_for_block_number(block_number);
        let block = era
            .blocks
            .iter()
            .find(|block| block.block.execution_block_number() == block_number)
            .unwrap();
        let block = block.block.message_merge().unwrap();
        let execution_payload = block.body.execution_payload.clone();
        let header = execution_payload.clone().into();
        let historical_batch = HistoricalBatch {
            state_roots: era.era_state.state.state_roots().clone().into(),
            block_roots: era.era_state.state.block_roots().clone().into(),
        };
        let slot = block.slot;
        // beacon block proof
        let hb_proof = historical_batch.build_block_root_proof(slot % 8192);
        let beacon_block_proof: FixedVector<B256, typenum::U14> = hb_proof.into();
        // execution block proof
        let mut execution_block_hash_proof = block.body.build_execution_block_hash_proof();
        let body_root_proof = block.build_body_root_proof();
        execution_block_hash_proof.extend(body_root_proof);
        let execution_block_proof: FixedVector<B256, typenum::U11> =
            execution_block_hash_proof.into();

        let proof = BlockProofHistoricalRoots {
            beacon_block_proof,
            beacon_block_root: block.tree_hash_root(),
            slot,
            execution_block_proof,
        };
        let header_with_proof = HeaderWithProof {
            header,
            proof: BlockHeaderProof::HistoricalRoots(proof),
        };
        // idk about this
        let encoded_transactions = execution_payload.transactions.as_ssz_bytes();
        let body = BlockBody::Merge(BlockBodyMerge::from_ssz_bytes(&encoded_transactions).unwrap());
        let receipts = self
            .execution_api
            .get_era_receipts(
                block_number,
                execution_payload.transactions.len() as u64,
                execution_payload.receipts_root,
            )
            .await
            .unwrap();
        Ok(AllBlockData {
            block: block_number,
            header_with_proof,
            body,
            receipts,
        })
    }

    async fn get_pre_deneb_block_data(&self, block_number: u64) -> anyhow::Result<AllBlockData> {
        let era = self.get_era_for_block_number(block_number);
        let block = era
            .blocks
            .iter()
            .find(|block| block.block.execution_block_number() == block_number)
            .unwrap();
        let block = block
            .block
            .message_capella()
            .map_err(|e| anyhow!("Unable to decode capella block: {e:?}"))?;
        let execution_payload = block.body.execution_payload.clone();
        let header = execution_payload.clone().into();

        let historical_batch = HistoricalBatch {
            state_roots: era.era_state.state.state_roots().clone().into(),
            block_roots: era.era_state.state.block_roots().clone().into(),
        };
        let slot = block.slot;
        // beacon block proof
        let hb_proof = historical_batch.build_block_root_proof(slot % 8192);
        let beacon_block_proof: FixedVector<B256, typenum::U13> = hb_proof.into();
        // execution block proof
        let mut execution_block_hash_proof = block.body.build_execution_block_hash_proof();
        let body_root_proof = block.build_body_root_proof();
        execution_block_hash_proof.extend(body_root_proof);
        let execution_block_proof: VariableList<B256, typenum::U12> =
            execution_block_hash_proof.into();
        let proof = BlockProofHistoricalSummaries {
            beacon_block_proof,
            beacon_block_root: block.tree_hash_root(),
            slot,
            execution_block_proof,
        };

        let header_with_proof = HeaderWithProof {
            header,
            proof: BlockHeaderProof::HistoricalSummaries(proof),
        };
        // idk about this
        let encoded_transactions = execution_payload.transactions.as_ssz_bytes();
        let body = BlockBody::Merge(
            BlockBodyMerge::from_ssz_bytes(&encoded_transactions)
                .map_err(|e| anyhow!("Unable to decode block body: {:?}", e))?,
        );
        // what are we going to do if this fails?
        let receipts = self
            .execution_api
            .get_era_receipts(
                block_number,
                execution_payload.transactions.len() as u64,
                execution_payload.receipts_root,
            )
            .await?;
        Ok(AllBlockData {
            block: block_number,
            header_with_proof,
            body,
            receipts,
        })
    }

    pub fn iter_blocks(mut self) -> impl Stream<Item = Option<AllBlockData>> {
        stream! {
        while self.current_block < self.ending_block {
            let block_number = self.current_block;
            self.current_block += 1;

            if block_number < MERGE_BLOCK {
                yield Some(self.get_pre_merge_block_data(block_number).unwrap());
            } else if block_number < CAPELLA_BLOCK {
                yield Some(self.get_pre_capella_block_data(block_number).await.unwrap());
            } else if block_number < DENEB_BLOCK {
                yield Some(self.get_pre_deneb_block_data(block_number).await.unwrap());
            } else {
                panic!("xxx");
            }
        }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml::Value;
    use ethportal_api::types::execution::header_with_proof_new::build_historical_roots_proof;
    use ethportal_api::types::execution::header_with_proof_new::build_historical_summaries_proof;
    use ethportal_api::types::execution::header_with_proof_new::BlockProofHistoricalRoots;
    use ethportal_api::types::execution::header_with_proof_new::BlockProofHistoricalSummaries;
    use ethportal_api::types::consensus::historical_summaries::{HistoricalSummaries, HistoricalSummary};
    use ethportal_api::types::consensus::beacon_block::BeaconBlockBellatrix;
    use ethportal_api::types::consensus::beacon_block::BeaconBlockCapella;


    #[rstest::rstest]
    #[case(15539558, 4702208, 575)]
    //#[case(15547621, 4710400, 576)]
    //#[case(15555729, 4718592, 577)]
    #[tokio::test]
    async fn xxx_bella(#[case] block_number: u64, #[case] slot: u64, #[case] epoch: u64) {
        println!("searching for era");
        let era_path = format!("../../test_assets/era1/m{}.era", epoch);
        let raw_era1 = std::fs::read(era_path).unwrap();
        let beacon_state = Era::deserialize_to_beacon_state(&raw_era1).unwrap();
        let block = Era::iter_blocks(raw_era1)
            .unwrap()
            .find(|block_result| {
                if let Ok(block) = block_result {
                    block.block.execution_block_number() == block_number
                } else {
                    false
                }
            });
        let block = block.unwrap().unwrap();
        let test_assets_dir = format!("../../crates/ethportal-api/src/assets/test/proofs/{}/", block_number);
        let historical_batch = HistoricalBatch {
            state_roots: beacon_state.state_roots().clone().into(),
            block_roots: beacon_state.block_roots().clone().into(),
        };
        let hb_raw = historical_batch.as_ssz_bytes();
        // write hb_raw to file
        let hb_path = format!("{}hb.ssz", test_assets_dir);
        std::fs::write(hb_path, hb_raw).unwrap();

        let block = block.block.as_bellatrix().unwrap();
        let block = block.message.clone();
        let block_raw = block.as_ssz_bytes();
        // write block_raw to file
        let block_path = format!("{}block.ssz", test_assets_dir);
        std::fs::write(block_path, block_raw).unwrap();
    }

    #[rstest::rstest]
    //#[case(17034870, 6209538, 759)]
    #[case(17042287, 6217730, 760)]
    #[case(17062257, 6238210, 762)]
    #[tokio::test]
    async fn xxx_cap(#[case] block_number: u64, #[case] slot: u64, #[case] epoch: u64) {
        println!("searching for era");
        let era_path = format!("../../test_assets/era1/m{}.era", epoch);
        let raw_era1 = std::fs::read(era_path).unwrap();
        let beacon_state = Era::deserialize_to_beacon_state(&raw_era1).unwrap();
        let block = Era::iter_blocks(raw_era1)
            .unwrap()
            .find(|block_result| {
                if let Ok(block) = block_result {
                    block.block.execution_block_number() == block_number
                } else {
                    false
                }
            });
        let block = block.unwrap().unwrap();
        let test_assets_dir = format!("../../crates/ethportal-api/src/assets/test/proofs/{}/", block_number);
        //
        //let raw_state = std::fs::read("../../portal-spec-tests/tests/mainnet/history/headers_with_proof/block_proofs_capella/historical_summaries_at_slot_8953856.ssz").unwrap();
        //let historical_summaries = HistoricalSummaries::from_ssz_bytes(&raw_historical_summaries).unwrap();

        let state_raw = beacon_state.as_ssz_bytes();
        let state_path = format!("{}state.ssz", test_assets_dir);
        std::fs::write(state_path, state_raw).unwrap();

        let block = block.block.as_capella().unwrap();
        let block = block.message.clone();
        let block_raw = block.as_ssz_bytes();
        // write block_raw to file
        let block_path = format!("{}block.ssz", test_assets_dir);
        std::fs::write(block_path, block_raw).unwrap();
    }


    #[rstest::rstest]
    #[case(15539558, 4702208, 575, "block_proofs_bellatrix/beacon_block_proof-15539558-cdf9ed89b0c43cda17398dc4da9cfc505e5ccd19f7c39e3b43474180f1051e01.yaml")]
    #[case(15547621, 4710400, 576, "block_proofs_bellatrix/beacon_block_proof-15547621-96a9313cd506e32893d46c82358569ad242bb32786bd5487833e0f77767aec2a.yaml")]
    #[case(15555729, 4718592, 577, "block_proofs_bellatrix/beacon_block_proof-15555729-c6fd396d54f61c6d0f1dd3653f81267b0378e9a0d638a229b24586d8fd0bc499.yaml")]
    #[tokio::test]
    async fn yyy_bella(#[case] block_number: u64, #[case] slot: u64, #[case] epoch: u64, #[case] file_path: &str) {
        let test_vector = std::fs::read_to_string(format!("../../portal-spec-tests/tests/mainnet/history/headers_with_proof/{}", file_path)).unwrap();
        let test_vector: Value = serde_yaml::from_str(&test_vector).unwrap();
        let actual_proof = BlockProofHistoricalRoots {
            beacon_block_proof: serde_yaml::from_value(test_vector["beacon_block_proof"].clone()).unwrap(),
            beacon_block_root: serde_yaml::from_value(test_vector["beacon_block_root"].clone()).unwrap(),
            execution_block_proof: serde_yaml::from_value(test_vector["execution_block_proof"].clone()).unwrap(),
            slot: serde_yaml::from_value(test_vector["slot"].clone()).unwrap(),
        };

        let test_assets_dir = format!("../../crates/ethportal-api/src/assets/test/proofs/{}/", block_number);
        let hb_path = format!("{}hb.ssz", test_assets_dir);
        let hb_raw = std::fs::read(hb_path).unwrap();
        let historical_batch = HistoricalBatch::from_ssz_bytes(&hb_raw).unwrap();
        let block_path = format!("{}block.ssz", test_assets_dir);
        let block_raw = std::fs::read(block_path).unwrap();
        let block = BeaconBlockBellatrix::from_ssz_bytes(&block_raw).unwrap();
        let proof = build_historical_roots_proof(slot, &historical_batch, block);

        assert_eq!(actual_proof, proof);
    }

    #[rstest::rstest]
    #[case(17034870, 6209538, 759, "block_proofs_capella/beacon_block_proof-17034870.yaml")]
    #[case(17042287, 6217730, 760, "block_proofs_capella/beacon_block_proof-17042287.yaml")]
    #[case(17062257, 6238210, 762, "block_proofs_capella/beacon_block_proof-17062257.yaml")]
    #[tokio::test]
    async fn yyy_cap(#[case] block_number: u64, #[case] slot: u64, #[case] epoch: u64, #[case] file_path: &str) {
        let test_vector = std::fs::read_to_string(format!("../../portal-spec-tests/tests/mainnet/history/headers_with_proof/{}", file_path)).unwrap();
        let test_vector: Value = serde_yaml::from_str(&test_vector).unwrap();
        let actual_proof = BlockProofHistoricalSummaries {
            beacon_block_proof: serde_yaml::from_value(test_vector["beacon_block_proof"].clone()).unwrap(),
            beacon_block_root: serde_yaml::from_value(test_vector["beacon_block_root"].clone()).unwrap(),
            execution_block_proof: serde_yaml::from_value(test_vector["execution_block_proof"].clone()).unwrap(),
            slot: serde_yaml::from_value(test_vector["slot"].clone()).unwrap(),
        };

        let test_assets_dir = format!("../../crates/ethportal-api/src/assets/test/proofs/{}/", block_number);
        let state_path = format!("{}state.ssz", test_assets_dir);
        let state_raw = std::fs::read(state_path).unwrap();
        let beacon_state = BeaconState::from_ssz_bytes(&state_raw, ForkName::Capella).unwrap();
        let beacon_state = beacon_state.as_capella().unwrap();
        let block_path = format!("{}block.ssz", test_assets_dir);
        let block_raw = std::fs::read(block_path).unwrap();
        let block = BeaconBlockCapella::from_ssz_bytes(&block_raw).unwrap();
        let proof = build_historical_summaries_proof(slot, &beacon_state, block);

        assert_eq!(actual_proof, proof);
    }
}

use std::{path::PathBuf, sync::Arc};

use tree_hash::TreeHash;
use ethportal_api::types::consensus::beacon_state::HistoricalBatch;
use alloy::primitives::{B256, U256, Bloom};
use async_stream::stream;
use e2store::{
    era::Era,
    era1::Era1,
    utils::{get_era1_files, get_era_files},
};
use ssz::{Decode, Encode};
use ssz_types::{VariableList, FixedVector, typenum};
use portal_bridge::DEFAULT_BASE_EL_ENDPOINT;
use ethportal_api::types::consensus::execution_payload::{ExecutionPayloadBellatrix, ExecutionPayloadCapella};
use ethportal_api::types::execution::block_body::BlockBodyMerge;
use ethportal_api::Header;
use portal_bridge::api::execution::ExecutionApi;
use ethportal_api::types::execution::{
    accumulator::EpochAccumulator,
    block_body::BlockBody,
    header_with_proof_new::{
        BlockHeaderProof, BlockProofHistoricalHashesAccumulator, BlockProofHistoricalRoots, HeaderWithProof, BlockProofHistoricalSummaries,
    },
    receipts::Receipts,
};
use futures::Stream;
use portal_bridge::bridge::utils::lookup_epoch_acc;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use trin_execution::era::binary_search::EraBinarySearch;
use trin_validation::{accumulator::PreMergeAccumulator, header_validator::HeaderValidator};
use url::Url;


const ERA1_EPOCH: u64 = 1892;
const MERGE_BLOCK: u64 = 16_000_000;
const CAPELLA_BLOCK: u64 = 17_000_000;
const DENEB_BLOCK: u64 = 18_000_000;

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
    raw_era1: Option<Vec<u8>>,
    epoch_accumulator: Option<Arc<EpochAccumulator>>,
    execution_api: ExecutionApi,
    first_era: Option<Arc<Era>>,
    second_era: Option<Arc<Era>>,
}

impl EpochReader {
    pub async fn new(epoch: u64, epoch_acc_path: PathBuf) -> anyhow::Result<Self> {
        let starting_block = epoch * 8192;
        let ending_block = starting_block + 8192;
        let mut raw_era1 = None;
        let mut epoch_accumulator = None;
        let mut first_era = None;
        let mut second_era = None;
        let http_client = Client::builder()
            .default_headers(HeaderMap::from_iter([(
                CONTENT_TYPE,
                HeaderValue::from_static("application/xml"),
            )]))
            .build()?;

        if epoch <= ERA1_EPOCH {
            let era1_paths = get_era1_files(&http_client).await?;
            let era1_path = era1_paths.get(&epoch).unwrap();
            raw_era1 = Some(
                http_client
                    .get(era1_path)
                    .send()
                    .await
                    .unwrap()
                    .bytes()
                    .await?
                    .to_vec(),
            );
            let epoch_index = starting_block / 8192;
            let header_validator = HeaderValidator::new();
            epoch_accumulator = Some(Arc::new(
                lookup_epoch_acc(
                    epoch_index,
                    &header_validator.pre_merge_acc,
                    &epoch_acc_path,
                )
                .await
                .unwrap(),
            ));
        }
        if epoch > ERA1_EPOCH {
            let starting_era = EraBinarySearch::find_era_file(http_client.clone(), starting_block)
                .await
                .unwrap();
            let ending_era = EraBinarySearch::find_era_file(http_client.clone(), ending_block)
                .await
                .unwrap();

            let starting_epoch = starting_era.epoch_index;
            let ending_epoch = ending_era.epoch_index;

            let era_links = get_era_files(&http_client).await?;
            let starting_era_path = era_links.get(&starting_epoch).unwrap();
            let starting_era = http_client
                .get(starting_era_path)
                .send()
                .await
                .unwrap()
                .bytes()
                .await?
                .to_vec();
            first_era = Some(Arc::new(Era::deserialize(&starting_era).unwrap()));
            if starting_epoch != ending_epoch {
                let ending_era_path = era_links.get(&ending_epoch).unwrap();
                let ending_era = http_client
                    .get(ending_era_path)
                    .send()
                    .await
                    .unwrap()
                    .bytes()
                    .await?
                    .to_vec();
                let ending_era = Era::deserialize(&ending_era).unwrap();
                second_era = Some(Arc::new(ending_era));
            }
        }
        let execution_api = ExecutionApi::new(
            Url::parse(DEFAULT_BASE_EL_ENDPOINT).unwrap(),
            Url::parse(DEFAULT_BASE_EL_ENDPOINT).unwrap(),
            10,
        ).await.unwrap();
        Ok(Self {
            epoch,
            current_block: starting_block, // Track the current block
            ending_block,
            raw_era1, epoch_accumulator, execution_api, first_era,
            second_era,
        })
    }

    fn get_era_for_block_number(&self, block_number: u64) -> &Arc<Era> {
        if block_number < MERGE_BLOCK {
            panic!("logic is bad")
        }
        if let Some(first_era) = &self.first_era {
            if first_era.contains(block_number) {
                return first_era;
            }
        }

        if let Some(second_era) = &self.second_era {
            if second_era.contains(block_number) {
                return second_era;
            }
        }

        panic!("logic is bad")
    }
    
    pub fn iter_blocks(mut self) -> impl Stream<Item = Option<AllBlockData>> {
        stream! {
        while self.current_block < self.ending_block {
            let block_number = self.current_block;
            self.current_block += 1;

            if block_number < MERGE_BLOCK {
                if let Some(raw_era1) = &self.raw_era1 {
                    let block_index = block_number % 8192;
                    let tuple = Era1::get_tuple_by_index(raw_era1, block_index);
                    let header = tuple.header.header;
                    let receipts = tuple.receipts.receipts;
                    let body = tuple.body.body;
                    let proof = PreMergeAccumulator::construct_proof(&header, &self.epoch_accumulator.clone().unwrap()).unwrap();
                    let proof = BlockProofHistoricalHashesAccumulator::new(proof.proof.clone().into()).unwrap();
                    let header_with_proof = HeaderWithProof {
                        header,
                        proof: BlockHeaderProof::HistoricalHashes(proof),
                    };
                    yield Some(AllBlockData {
                        block: block_number,
                        header_with_proof,
                        body,
                        receipts,
                    });
                } else {
                    yield None;
                }
            } else {
                let era = self.get_era_for_block_number(block_number);
                if block_number < CAPELLA_BLOCK {
                    let block = era.blocks.iter().find(|block| block.block.execution_block_number() == block_number).unwrap();
                    let block = block.block.message_merge().unwrap();
                    let execution_payload = block.body.execution_payload.clone();
                    let header = get_header(&execution_payload);
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
                    let execution_block_proof: FixedVector<B256, typenum::U11> = execution_block_hash_proof.into();

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
                    let receipts = self.execution_api.get_era_receipts(
                        block_number,
                        execution_payload.transactions.len() as u64,
                        execution_payload.receipts_root,
                    ).await.unwrap();
                    yield Some(AllBlockData {
                        block: block_number,
                        header_with_proof,
                        body,
                        receipts,
                    });
                } else if block_number < DENEB_BLOCK {
                    let block = era.blocks.iter().find(|block| block.block.execution_block_number() == block_number).unwrap();
                    let block = block.block.message_capella().unwrap();
                    let execution_payload = block.body.execution_payload.clone();
                    let header = get_header_capella(&execution_payload);
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
                    let execution_block_proof: VariableList<B256, typenum::U12> = execution_block_hash_proof.into();

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
                    let body = BlockBody::Merge(BlockBodyMerge::from_ssz_bytes(&encoded_transactions).unwrap());
                    let receipts = self.execution_api.get_era_receipts(
                        block_number,
                        execution_payload.transactions.len() as u64,
                        execution_payload.receipts_root,
                    ).await.unwrap();
                    yield Some(AllBlockData {
                        block: block_number,
                        header_with_proof,
                        body,
                        receipts,
                    });
                } else {
                    unimplemented!();
                }
            }
        }
        }
    }
}

fn get_header(execution_payload: &ExecutionPayloadBellatrix) -> Header {
    let transactions_root = execution_payload.transactions.tree_hash_root();
    let withdrawals_root = None;
    let header = Header {
        parent_hash: execution_payload.parent_hash,
        uncles_hash: B256::default(),
        author: execution_payload.fee_recipient,
        state_root: execution_payload.state_root,
        transactions_root,
        receipts_root: execution_payload.receipts_root,
        // what do here?
        logs_bloom: Bloom::from_ssz_bytes(&execution_payload.logs_bloom.as_ssz_bytes()).unwrap(),
        // what do here?
        difficulty: U256::from(0),
        number: execution_payload.block_number,
        gas_limit: U256::from(execution_payload.gas_limit),
        gas_used: U256::from(execution_payload.gas_used),
        timestamp: execution_payload.timestamp,
        extra_data: execution_payload.extra_data.to_vec(),
        mix_hash: None,
        nonce: None,
        base_fee_per_gas: Some(execution_payload.base_fee_per_gas),
        withdrawals_root,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
    };
    header
}

fn get_header_capella(execution_payload: &ExecutionPayloadCapella) -> Header {
    let transactions_root = execution_payload.transactions.tree_hash_root();
    let withdrawals_root = Some(execution_payload.withdrawals.tree_hash_root());
    let header = Header {
        parent_hash: execution_payload.parent_hash,
        uncles_hash: B256::default(),
        author: execution_payload.fee_recipient,
        state_root: execution_payload.state_root,
        transactions_root,
        receipts_root: execution_payload.receipts_root,
        // what do here?
        logs_bloom: Bloom::from_ssz_bytes(&execution_payload.logs_bloom.as_ssz_bytes()).unwrap(),
        // what do here?
        difficulty: U256::from(0),
        number: execution_payload.block_number,
        gas_limit: U256::from(execution_payload.gas_limit),
        gas_used: U256::from(execution_payload.gas_used),
        timestamp: execution_payload.timestamp,
        extra_data: execution_payload.extra_data.to_vec(),
        mix_hash: None,
        nonce: None,
        base_fee_per_gas: Some(execution_payload.base_fee_per_gas),
        withdrawals_root,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
    };
    header
}

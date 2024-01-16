use std::{
    fs,
    ops::Range,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, bail};
use ssz::Decode;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn, Instrument};

use crate::{
    api::execution::ExecutionApi,
    gossip::gossip_history_content,
    stats::{HistoryBlockStats, StatsReporter},
    types::{
        full_header::FullHeader,
        mode::{BridgeMode, ModeType},
    },
    utils::{read_test_assets_from_file, TestAssets},
};
use ethportal_api::{
    jsonrpsee::http_client::HttpClient,
    types::execution::{
        accumulator::EpochAccumulator,
        block_body::{
            BlockBody, BlockBodyLegacy, BlockBodyMerge, BlockBodyShanghai, MERGE_TIMESTAMP,
            SHANGHAI_TIMESTAMP,
        },
        header::{AccumulatorProof, BlockHeaderProof, Header, HeaderWithProof, SszNone},
        receipts::Receipts,
    },
    utils::bytes::hex_encode,
    BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, EpochAccumulatorKey, HistoryContentKey,
    HistoryContentValue,
};
use trin_validation::{
    accumulator::MasterAccumulator,
    constants::{EPOCH_SIZE as EPOCH_SIZE_USIZE, MERGE_BLOCK_NUMBER},
    oracle::HeaderOracle,
};

// todo: calculate / test optimal saturation delay
const HEADER_SATURATION_DELAY: u64 = 10; // seconds
const LATEST_BLOCK_POLL_RATE: u64 = 5; // seconds
const EPOCH_SIZE: u64 = EPOCH_SIZE_USIZE as u64;

pub struct HistoryBridge {
    pub mode: BridgeMode,
    pub portal_clients: Vec<HttpClient>,
    pub execution_api: ExecutionApi,
    pub header_oracle: HeaderOracle,
    pub epoch_acc_path: PathBuf,
}

impl HistoryBridge {
    pub fn new(
        mode: BridgeMode,
        execution_api: ExecutionApi,
        portal_clients: Vec<HttpClient>,
        header_oracle: HeaderOracle,
        epoch_acc_path: PathBuf,
    ) -> Self {
        Self {
            mode,
            portal_clients,
            execution_api,
            header_oracle,
            epoch_acc_path,
        }
    }
}

impl HistoryBridge {
    pub async fn launch(&self) {
        info!("Launching bridge mode: {:?}", self.mode);
        let latest_block = self.execution_api.get_latest_block_number().await.expect(
            "Error launching bridge in backfill mode. Unable to get latest block from provider.",
        );
        if let Err(msg) = self.mode.validate_against_latest(latest_block) {
            warn!(
                "Error launching bridge in {:?} mode. {:?}",
                self.mode,
                msg.to_string()
            );
            return;
        };
        match self.mode.clone() {
            BridgeMode::Test(path) => self.launch_test(path).await,
            BridgeMode::Latest => self.launch_latest(latest_block).await,
            BridgeMode::Single(val) => self.launch_single(val).await,
            BridgeMode::Range(val) => self.launch_range(val).await,
            BridgeMode::Backfill(val) => self.launch_backfill(val, latest_block).await,
        }
        info!("Bridge mode: {:?} complete.", self.mode);
    }

    async fn launch_test(&self, test_path: PathBuf) {
        let assets: TestAssets = read_test_assets_from_file(test_path);
        let assets = assets
            .into_history_assets()
            .expect("Error parsing history test assets.");

        // test files have no block number data, so we report all gossiped content at height 0.
        let block_stats = Arc::new(Mutex::new(HistoryBlockStats::new(0)));
        for asset in assets.0.into_iter() {
            let _ = gossip_history_content(
                &self.portal_clients,
                asset.content_key.clone(),
                asset.content_value,
                block_stats.clone(),
            )
            .await;
            if let HistoryContentKey::BlockHeaderWithProof(_) = asset.content_key {
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    // Devops nodes don't have websockets available, so we can't actually poll the latest block.
    // Instead we loop on a short interval and fetch the latest blocks not yet served.
    async fn launch_latest(&self, latest_block: u64) {
        let mut block_index = latest_block;
        loop {
            sleep(Duration::from_secs(LATEST_BLOCK_POLL_RATE)).await;
            let latest_block = match self.execution_api.get_latest_block_number().await {
                Ok(val) => val,
                Err(msg) => {
                    warn!("error getting latest block, skipping iteration: {msg:?}");
                    continue;
                }
            };
            if latest_block > block_index {
                let gossip_range = Range {
                    start: block_index,
                    end: latest_block + 1,
                };
                info!("Discovered new blocks to gossip: {gossip_range:?}");
                for height in gossip_range.clone() {
                    let portal_clients = self.portal_clients.clone();
                    let execution_api = self.execution_api.clone();
                    tokio::spawn(async move {
                        let _ = Self::serve_full_block(height, None, portal_clients, execution_api)
                            .in_current_span()
                            .await;
                    });
                }
                block_index = gossip_range.end;
            }
        }
    }

    async fn launch_single(&self, mode: ModeType) {
        match mode {
            ModeType::Block(block_number) => {
                self.launch_range(Range {
                    start: block_number,
                    end: block_number + 1,
                }).await;
            }
            ModeType::Epoch(epoch_number) => {
                self.launch_range(Range {
                    start: epoch_number * EPOCH_SIZE,
                    end: (epoch_number + 1) * EPOCH_SIZE,
                }).await;
            }
            ModeType::Range(_) => panic!("Invalid mode type for single mode, range isn't supported. Use `range:` prefix instead."),
        };
    }

    async fn launch_range(&self, range: Range<u64>) {
        // check if range crosses epoch boundary
        let start_epoch = range.start / EPOCH_SIZE;
        let end_epoch = range.end / EPOCH_SIZE;
        // looped is true if the range crosses an epoch boundary
        let looped = start_epoch != end_epoch;
        let (mut start_block, mut end_block, mut epoch_index) = {
            let end_block = match looped {
                true => (start_epoch + 1) * EPOCH_SIZE,
                false => range.end,
            };
            (range.start, end_block, start_epoch)
        };
        // per-loop range of blocks to gossip
        let mut gossip_range = Range {
            start: start_block,
            end: end_block,
        };
        while epoch_index <= end_epoch {
            // Using epoch_size chunks & epoch boundaries ensures that every
            // "chunk" shares an epoch accumulator avoiding the need to
            // look up the epoch acc on a header by header basis
            let epoch_acc = if gossip_range.end <= MERGE_BLOCK_NUMBER {
                match self.get_epoch_acc(epoch_index).await {
                    Ok(val) => Some(val),
                    Err(msg) => {
                        warn!("Unable to find epoch acc for gossip range: {gossip_range:?}. Skipping iteration: {msg:?}");
                        continue;
                    }
                }
            } else {
                None
            };
            info!("fetching headers in range: {gossip_range:?}");
            for height in gossip_range.clone() {
                let epoch_acc = epoch_acc.clone();
                let portal_clients = self.portal_clients.clone();
                let execution_api = self.execution_api.clone();
                tokio::spawn(async move {
                    let _ =
                        Self::serve_full_block(height, epoch_acc, portal_clients, execution_api)
                            .in_current_span()
                            .await;
                });
            }
            // update index values if we're looping
            epoch_index += 1;
            start_block = epoch_index * EPOCH_SIZE;
            if epoch_index == end_epoch {
                end_block = range.end;
            } else {
                end_block = start_block + EPOCH_SIZE;
            }
            gossip_range = Range {
                start: start_block,
                end: end_block,
            };
        }
    }

    async fn launch_backfill(&self, mode: ModeType, latest_block: u64) {
        let (mut start_block, mut end_block, mut epoch_index) = match mode {
            // end block will be same for an epoch in single & backfill modes
            ModeType::Epoch(epoch_number) => (
                epoch_number * EPOCH_SIZE,
                ((epoch_number + 1) * EPOCH_SIZE),
                epoch_number,
            ),
            ModeType::Block(block) => {
                let epoch_index = block / EPOCH_SIZE;
                let end_block = (epoch_index + 1) * EPOCH_SIZE;
                (block, end_block, epoch_index)
            }
            ModeType::Range(_) => panic!("Invalid mode type for backfill mode, range isn't supported. Use `range:` prefix instead."),
        };
        let current_epoch = latest_block / EPOCH_SIZE;
        // per-loop range of blocks to gossip
        let mut gossip_range = Range {
            start: start_block,
            end: end_block,
        };
        while epoch_index <= current_epoch {
            // Using epoch_size chunks & epoch boundaries ensures that every
            // "chunk" shares an epoch accumulator avoiding the need to
            // look up the epoch acc on a header by header basis
            let epoch_acc = if gossip_range.end <= MERGE_BLOCK_NUMBER {
                match self.get_epoch_acc(epoch_index).await {
                    Ok(val) => Some(val),
                    Err(msg) => {
                        warn!("Unable to find epoch acc for gossip range: {gossip_range:?}. Skipping iteration: {msg:?}");
                        continue;
                    }
                }
            } else {
                None
            };
            info!("fetching headers in range: {gossip_range:?}");
            for height in gossip_range.clone() {
                let epoch_acc = epoch_acc.clone();
                let portal_clients = self.portal_clients.clone();
                let execution_api = self.execution_api.clone();
                tokio::spawn(async move {
                    let _ =
                        Self::serve_full_block(height, epoch_acc, portal_clients, execution_api)
                            .in_current_span()
                            .await;
                });
            }
            // update index values if we're looping
            epoch_index += 1;
            start_block = epoch_index * EPOCH_SIZE;
            end_block = start_block + EPOCH_SIZE;
            gossip_range = Range {
                start: start_block,
                end: end_block,
            };
        }
    }

    async fn serve_full_block(
        height: u64,
        epoch_acc: Option<Arc<EpochAccumulator>>,
        portal_clients: Vec<HttpClient>,
        execution_api: ExecutionApi,
    ) -> anyhow::Result<()> {
        info!("Serving block: {height}");
        let mut full_header = execution_api.get_header(height).await?;
        if full_header.header.number <= MERGE_BLOCK_NUMBER {
            full_header.epoch_acc = epoch_acc;
        }
        let block_stats = Arc::new(Mutex::new(HistoryBlockStats::new(
            full_header.header.number,
        )));
        HistoryBridge::gossip_header(&full_header, &portal_clients, block_stats.clone()).await?;
        // Sleep for 10 seconds to allow headers to saturate network,
        // since they must be available for body / receipt validation.
        sleep(Duration::from_secs(HEADER_SATURATION_DELAY)).await;
        HistoryBridge::construct_and_gossip_block_body(
            &full_header,
            &portal_clients,
            &execution_api,
            block_stats.clone(),
        )
        .await
        .map_err(|err| anyhow!("Error gossiping block body #{height:?}: {err:?}"))?;

        HistoryBridge::construct_and_gossip_receipt(
            &full_header,
            &portal_clients,
            &execution_api,
            block_stats.clone(),
        )
        .await
        .map_err(|err| anyhow!("Error gossiping receipt #{height:?}: {err:?}"))?;
        if let Ok(stats) = block_stats.lock() {
            stats.report();
        } else {
            warn!("Error displaying history gossip stats. Unable to acquire lock.");
        }
        Ok(())
    }

    async fn gossip_header(
        full_header: &FullHeader,
        portal_clients: &Vec<HttpClient>,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        debug!("Serving header: {}", full_header.header.number);
        if full_header.header.number < MERGE_BLOCK_NUMBER && full_header.epoch_acc.is_none() {
            bail!("Invalid header, expected to have epoch accumulator");
        }
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
            block_hash: full_header.header.hash().to_fixed_bytes(),
        });
        // validate pre-merge
        let content_value = match &full_header.epoch_acc {
            Some(epoch_acc) => {
                // Fetch HeaderRecord from EpochAccumulator for validation
                let header_index = full_header.header.number % EPOCH_SIZE;
                let header_record = &epoch_acc[header_index as usize];

                // Validate Header
                if header_record.block_hash != full_header.header.hash() {
                    bail!(
                        "Header hash doesn't match record in local accumulator: {:?} - {:?}",
                        full_header.header.hash(),
                        header_record.block_hash
                    );
                }
                // Construct HeaderWithProof
                let header_with_proof =
                    HistoryBridge::construct_proof(full_header.header.clone(), epoch_acc).await?;
                HistoryContentValue::BlockHeaderWithProof(header_with_proof)
            }
            None => {
                let header_with_proof = HeaderWithProof {
                    header: full_header.header.clone(),
                    proof: BlockHeaderProof::None(SszNone { value: None }),
                };
                HistoryContentValue::BlockHeaderWithProof(header_with_proof)
            }
        };
        debug!(
            "Gossip: Block #{:?} HeaderWithProof",
            full_header.header.number
        );
        let _ =
            gossip_history_content(portal_clients, content_key, content_value, block_stats).await;
        Ok(())
    }

    /// Attempt to lookup an epoch accumulator from local portal-accumulators path provided via cli
    /// arg. Gossip the epoch accumulator if found.
    async fn get_epoch_acc(&self, epoch_index: u64) -> anyhow::Result<Arc<EpochAccumulator>> {
        let epoch_hash = self.header_oracle.master_acc.historical_epochs[epoch_index as usize];
        let epoch_hash_pretty = hex_encode(epoch_hash);
        let epoch_hash_pretty = epoch_hash_pretty.trim_start_matches("0x");
        let epoch_acc_path = format!(
            "{}/bridge_content/0x03{epoch_hash_pretty}.portalcontent",
            self.epoch_acc_path.display(),
        );
        let local_epoch_acc = match fs::read(&epoch_acc_path) {
            Ok(val) => EpochAccumulator::from_ssz_bytes(&val).map_err(|err| anyhow!("{err:?}"))?,
            Err(_) => {
                return Err(anyhow!(
                    "Unable to find local epoch acc at path: {epoch_acc_path:?}"
                ))
            }
        };
        // Gossip epoch acc to network if found locally
        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey { epoch_hash });
        let content_value = HistoryContentValue::EpochAccumulator(local_epoch_acc.clone());
        // create unique stats for epoch accumulator, since it's rarely gossiped
        let block_stats = Arc::new(Mutex::new(HistoryBlockStats::new(epoch_index * EPOCH_SIZE)));
        let _ = gossip_history_content(
            &self.portal_clients,
            content_key,
            content_value,
            block_stats,
        )
        .await;
        Ok(Arc::new(local_epoch_acc))
    }

    async fn construct_and_gossip_receipt(
        full_header: &FullHeader,
        portal_clients: &Vec<HttpClient>,
        execution_api: &ExecutionApi,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        debug!("Serving receipt: {:?}", full_header.header.number);
        let receipts = match full_header.txs.len() {
            0 => Receipts {
                receipt_list: vec![],
            },
            _ => {
                execution_api
                    .get_trusted_receipts(&full_header.tx_hashes.hashes)
                    .await?
            }
        };

        // Validate Receipts
        let receipts_root = receipts.root()?;
        if receipts_root != full_header.header.receipts_root {
            bail!(
                "Receipts root doesn't match header receipts root: {receipts_root:?} - {:?}",
                full_header.header.receipts_root
            );
        }
        let content_key = HistoryContentKey::BlockReceipts(BlockReceiptsKey {
            block_hash: full_header.header.hash().to_fixed_bytes(),
        });
        let content_value = HistoryContentValue::Receipts(receipts);
        debug!("Gossip: Block #{:?} Receipts", full_header.header.number,);
        let _ =
            gossip_history_content(portal_clients, content_key, content_value, block_stats).await;
        Ok(())
    }

    async fn construct_and_gossip_block_body(
        full_header: &FullHeader,
        portal_clients: &Vec<HttpClient>,
        execution_api: &ExecutionApi,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let txs = full_header.txs.clone();
        let block_body = if full_header.header.timestamp > SHANGHAI_TIMESTAMP {
            if !full_header.uncles.is_empty() {
                bail!("Invalid block: Shanghai block contains uncles");
            }
            let withdrawals = match full_header.withdrawals.clone() {
                Some(val) => val,
                None => bail!("Invalid block: Shanghai block missing withdrawals"),
            };
            BlockBody::Shanghai(BlockBodyShanghai { txs, withdrawals })
        } else if full_header.header.timestamp > MERGE_TIMESTAMP {
            if !full_header.uncles.is_empty() {
                bail!("Invalid block: Merge block contains uncles");
            }
            BlockBody::Merge(BlockBodyMerge { txs })
        } else {
            let uncles = match full_header.uncles.len() {
                0 => vec![],
                _ => {
                    execution_api
                        .get_trusted_uncles(&full_header.uncles)
                        .await?
                }
            };
            BlockBody::Legacy(BlockBodyLegacy { txs, uncles })
        };
        block_body.validate_against_header(&full_header.header)?;

        let content_key = HistoryContentKey::BlockBody(BlockBodyKey {
            block_hash: full_header.header.hash().to_fixed_bytes(),
        });
        let content_value = HistoryContentValue::BlockBody(block_body);
        debug!("Gossip: Block #{:?} BlockBody", full_header.header.number);
        let _ =
            gossip_history_content(portal_clients, content_key, content_value, block_stats).await;
        Ok(())
    }

    /// Create a proof for the given header / epoch acc
    async fn construct_proof(
        header: Header,
        epoch_acc: &EpochAccumulator,
    ) -> anyhow::Result<HeaderWithProof> {
        let proof = MasterAccumulator::construct_proof(&header, epoch_acc)?;
        let proof = BlockHeaderProof::AccumulatorProof(AccumulatorProof { proof });
        Ok(HeaderWithProof { header, proof })
    }
}

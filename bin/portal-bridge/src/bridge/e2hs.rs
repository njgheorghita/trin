use std::sync::{Arc, Mutex};

use alloy::primitives::B256;
use anyhow::bail;
use e2store::e2hs::{BlockTuple, E2HS};
use ethportal_api::{
    jsonrpsee::http_client::HttpClient,
    types::execution::{
        block_body::BlockBody, header_with_proof::HeaderWithProof, receipts::Receipts,
    },
    HistoryContentKey, HistoryContentValue,
};
use futures::future::join_all;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::timeout,
};
use tracing::{error, info};
use trin_metrics::bridge::BridgeMetricsReporter;
use trin_validation::header_validator::HeaderValidator;

use crate::{
    bridge::history::SERVE_BLOCK_TIMEOUT,
    put_content::gossip_history_content,
    stats::{HistoryBlockStats, StatsReporter},
    types::mode::BridgeMode,
};

#[derive(Debug)]
pub enum E2HSBridgeMode {
    FourFours,
    Random,
    Ordered,
}

#[derive(Debug)]
pub struct E2HSBridge {
    mode: BridgeMode,
    portal_client: HttpClient,
    metrics: BridgeMetricsReporter,
    gossip_semaphore: Arc<Semaphore>,
    header_validator: HeaderValidator,
}

impl E2HSBridge {
    pub fn new(
        mode: BridgeMode,
        portal_client: HttpClient,
        gossip_limit: usize,
    ) -> anyhow::Result<Self> {
        let gossip_semaphore = Arc::new(Semaphore::new(gossip_limit));
        let metrics = BridgeMetricsReporter::new("e2hs".to_string(), &format!("{mode:?}"));
        let header_validator = HeaderValidator::new();
        Ok(Self {
            mode,
            portal_client,
            metrics,
            gossip_semaphore,
            header_validator,
        })
    }

    pub async fn launch(&self) {
        info!("Launching E2HS bridge in {:?} mode", self.mode);
        match self.mode {
            BridgeMode::E2HS => {
                self.random().await;
            }
            _ => {
                unimplemented!("Unsupported mode: {:?}", self.mode);
            }
        }
    }

    async fn random(&self) {
        info!("Launching Random mode");
        self.gossip_e2hs_file().await;
    }

    async fn gossip_e2hs_file(&self) {
        let raw_e2hs = std::fs::read("./test_assets/era1/mainnet-00000-d4e56740.e2hs")
            .expect("Failed to read e2hs file");
        let mut serve_block_tuple_handles = vec![];
        let block_stream = E2HS::iter_tuples(raw_e2hs).expect("xxx");
        for block_tuple in block_stream {
            if let Err(err) = self.validate_block_tuple(&block_tuple) {
                error!("Failed to validate block tuple: {:?}", err);
                continue;
            }
            let permit = self
                .gossip_semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("Failed to acquire gossip semaphore");
            self.metrics.report_current_block(
                block_tuple
                    .header_with_proof
                    .header_with_proof
                    .header
                    .number as i64,
            );
            let handle = Self::spawn_serve_block_tuple(
                self.portal_client.clone(),
                block_tuple,
                permit,
                self.metrics.clone(),
            );
            serve_block_tuple_handles.push(handle);
        }
        join_all(serve_block_tuple_handles).await;
    }

    fn spawn_serve_block_tuple(
        portal_client: HttpClient,
        block_tuple: BlockTuple,
        permit: OwnedSemaphorePermit,
        metrics: BridgeMetricsReporter,
    ) -> JoinHandle<()> {
        let number = block_tuple
            .header_with_proof
            .header_with_proof
            .header
            .number;
        info!("Spawning serve block tuple for block {}", number);
        let block_stats = Arc::new(Mutex::new(HistoryBlockStats::new(number)));
        tokio::spawn(async move {
            let timer = metrics.start_process_timer("spawn_serve_block_tuple");
            match timeout(
                SERVE_BLOCK_TIMEOUT,
                Self::serve_block_tuple(
                    portal_client,
                    block_tuple,
                    block_stats.clone(),
                    metrics.clone(),
                ),
            )
            .await
            {
                Ok(Ok(())) => {
                    info!("Served block {}", number);
                }
                Ok(Err(e)) => {
                    error!("Failed to serve block {}: {:?}", number, e);
                }
                Err(_) => {
                    error!("Timed out serving block {}", number);
                }
            }
            metrics.stop_process_timer(timer);
            drop(permit);
        })
    }

    async fn serve_block_tuple(
        portal_client: HttpClient,
        block_tuple: BlockTuple,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
        _metrics: BridgeMetricsReporter,
    ) -> anyhow::Result<()> {
        info!(
            "Serving block tuple for block #{}",
            block_tuple
                .header_with_proof
                .header_with_proof
                .header
                .number
        );

        let header_hash = block_tuple
            .header_with_proof
            .header_with_proof
            .header
            .hash_slow();

        // gossip header by hash
        Self::gossip_header_by_hash(
            block_tuple.header_with_proof.header_with_proof.clone(),
            portal_client.clone(),
            block_stats.clone(),
        )
        .await?;
        // should we sleep here to let header propagate? maybe not?

        // gossip header by number
        Self::gossip_header_by_number(
            block_tuple.header_with_proof.header_with_proof.clone(),
            portal_client.clone(),
            block_stats.clone(),
        )
        .await?;

        // gossip body
        Self::gossip_body(
            block_tuple.body.body.clone(),
            header_hash,
            portal_client.clone(),
            block_stats.clone(),
        )
        .await?;

        // gossip receipts
        Self::gossip_receipts(
            block_tuple.receipts.receipts.clone(),
            header_hash,
            portal_client.clone(),
            block_stats.clone(),
        )
        .await?;
        Ok(())
    }

    async fn gossip_header_by_hash(
        header_with_proof: HeaderWithProof,
        portal_client: HttpClient,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let header_hash = header_with_proof.header.hash_slow();
        let hwp_by_hash_content_key = HistoryContentKey::new_block_header_by_hash(header_hash);
        let hwp_content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);
        if let Err(err) = gossip_history_content(
            portal_client,
            hwp_by_hash_content_key.clone(),
            hwp_content_value,
            block_stats,
        )
        .await
        {
            error!(
                "Failed to gossip history content key: {:?} - {:?}",
                hwp_by_hash_content_key, err
            );
        }
        Ok(())
    }

    async fn gossip_header_by_number(
        header_with_proof: HeaderWithProof,
        portal_client: HttpClient,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let header_number = header_with_proof.header.number;
        let hwp_by_number_content_key =
            HistoryContentKey::new_block_header_by_number(header_number);
        let hwp_content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);
        if let Err(err) = gossip_history_content(
            portal_client,
            hwp_by_number_content_key.clone(),
            hwp_content_value,
            block_stats,
        )
        .await
        {
            error!(
                "Failed to gossip history content key: {:?} - {:?}",
                hwp_by_number_content_key, err
            );
        }
        Ok(())
    }

    async fn gossip_body(
        body: BlockBody,
        header_hash: B256,
        portal_client: HttpClient,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let body_content_key = HistoryContentKey::new_block_body(header_hash);
        let body_content_value = HistoryContentValue::BlockBody(body);
        if let Err(err) = gossip_history_content(
            portal_client,
            body_content_key.clone(),
            body_content_value,
            block_stats,
        )
        .await
        {
            error!(
                "Failed to gossip history content key: {:?} - {:?}",
                body_content_key, err
            );
        }
        Ok(())
    }

    async fn gossip_receipts(
        receipts: Receipts,
        header_hash: B256,
        portal_client: HttpClient,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let receipts_content_key = HistoryContentKey::new_block_receipts(header_hash);
        let receipts_content_value = HistoryContentValue::Receipts(receipts);
        if let Err(err) = gossip_history_content(
            portal_client,
            receipts_content_key.clone(),
            receipts_content_value,
            block_stats,
        )
        .await
        {
            error!(
                "Failed to gossip history content key: {:?} - {:?}",
                receipts_content_key, err
            );
        }
        Ok(())
    }

    fn validate_block_tuple(&self, block_tuple: &BlockTuple) -> anyhow::Result<()> {
        self.header_validator
            .validate_header_with_proof(&block_tuple.header_with_proof.header_with_proof)?;
        let receipts = &block_tuple.receipts.receipts;
        let receipts_root = receipts.root();
        if receipts_root
            != block_tuple
                .header_with_proof
                .header_with_proof
                .header
                .receipts_root
        {
            bail!("Receipts root mismatch");
        }
        let body = &block_tuple.body.body;
        body.validate_against_header(&block_tuple.header_with_proof.header_with_proof.header)?;
        Ok(())
    }
}

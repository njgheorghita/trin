use ethportal_api::jsonrpsee::http_client::HttpClient;
use futures::future::join_all;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::{Semaphore, OwnedSemaphorePermit};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use trin_metrics::bridge::BridgeMetricsReporter;
use tracing::{info, error};
use crate::bridge::history::SERVE_BLOCK_TIMEOUT;

#[derive(Debug)]
pub enum E2HSBridgeMode {
    FourFours,
    Random,
    Ordered,
}

pub struct E2HSBridge {
    mode: E2HSBridgeMode,
    portal_client: HttpClient,
    http_client: Client,
    metrics: BridgeMetricsReporter,
    gossip_semaphore: Arc<Semaphore>,
}

impl E2HSBridge {
    pub fn new(
        mode: E2HSBridgeMode,
        portal_client: HttpClient,
        http_client: Client,
        metrics: BridgeMetricsReporter,
        gossip_limit: usize,
    ) -> anyhow::Result<Self> {
        let gossip_semaphore = Arc::new(Semaphore::new(gossip_limit));
        Ok(Self {
            mode,
            portal_client,
            http_client,
            metrics,
            gossip_semaphore,
        })
    }

    pub async fn launch(&self) {
        info!("Launching E2HS bridge in {:?} mode", self.mode);
        match self.mode {
            E2HSBridgeMode::FourFours => {
                //self.four_fours().await;
                ();
            }
            E2HSBridgeMode::Random => {
                self.random().await;
            }
            E2HSBridgeMode::Ordered => {
                //self.ordered().await;
                ();
            }
        }
    }

    async fn random(&self) {
        info!("Launching Random mode");
        let e2hs_files = get_shuffled_e2hs_files().await.expect("x");
        for file in e2hs_files {
            self.gossip_e2hs_file(file).await;
        }
    }

    async fn gossip_e2hs_file(&self, file: String) {
        let raw_e2hs = self
            .http_client
            .get(file)
            .send()
            .await
            .expect("Failed to fetch e2hs file")
            .bytes()
            .await
            .expect("Failed to read e2hs file");
        let mut serve_block_tuple_handles = vec![];
        for block_tuple in E2HS::iter_tuples(raw_e2hs.to_vec()) {
            let permit = self.gossip_semaphore.clone()
                .acquire_owned()
                .await
                .expect("Failed to acquire gossip semaphore");
            self.metrics.report_current_block(block_tuple.header_with_proof.header.number);
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
        let number = block_tuple.header_with_proof.header.number;
        info!("Spawning serve block tuple for block {}", number);
        tokio::spawn(async move {
            let timer = metrics.start_process_timer("spawn_serve_block_tuple");
            match timeout(
                SERVE_BLOCK_TIMEOUT,
                Self::serve_block_tuple(
                    portal_client,
                    block_tuple,
                    permit,
                    metrics.clone(),
                )).await
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
        _permit: OwnedSemaphorePermit,
        _metrics: BridgeMetricsReporter,
    ) -> anyhow::Result<()> {
        info!("Serving block tuple for block {}", block_tuple.header_with_proof.header.number);
        Ok(())
    }

    async fn validate_and_gossip_header_with_proof(
        &self,
        header_with_proof: HeaderWithProof,
    ) -> anyhow::Result<()> {
        let header = header_with_proof.header;
        let proof = header_with_proof.proof;
        let block_number = header.number;
        let block_hash = header.hash();
        let proof_hash = proof.hash();
        let proof_valid = proof.verify(&block_hash);
        if !proof_valid {
            anyhow::bail!("Proof for block {} is invalid", block_number);
        }
        let gossip = Gossip {
            block_number,
            block_hash,
            proof_hash,
        };
        self.gossip(gossip).await;
        Ok(())
    }

    async fn validate_and_gossip_body(&self, body: Body) -> anyhow::Result<()> {
        let block_number = body.header.number;
        let block_hash = body.header.hash();
        let body_hash = body.hash();
        if block_hash != body_hash {
            anyhow::bail!("Body for block {} is invalid", block_number);
        }
        let gossip = Gossip {
            block_number,
            block_hash,
            body_hash,
        };
        self.gossip(gossip).await;
        Ok(())
    }

    async fn validate_and_gossip_receipts(&self, receipts: Receipts) -> anyhow::Result<()> {
        let block_number = receipts.header.number;
        let block_hash = receipts.header.hash();
        let receipts_hash = receipts.hash();
        if block_hash != receipts_hash {
            anyhow::bail!("Receipts for block {} are invalid", block_number);
        }
        let gossip = Gossip {
            block_number,
            block_hash,
            receipts_hash,
        };
        self.gossip(gossip).await;
        Ok(())
    }
}






























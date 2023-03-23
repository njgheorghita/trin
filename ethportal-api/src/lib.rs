//! # ethportal-api
//!
//! `ethportal_api` is a collection of Portal Network APIs and types.
#![warn(clippy::unwrap_used)]

mod discv5;
mod history;
pub mod types;
mod web3;

pub use crate::discv5::{Discv5ApiClient, Discv5ApiServer};
pub use history::{HistoryNetworkApiClient, HistoryNetworkApiServer};
pub use web3::{Web3ApiClient, Web3ApiServer};

// Re-exports trin-types
pub use trin_types::content_item::{ContentItem, HistoryContentItem};
pub use trin_types::content_key::{
    BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, EpochAccumulatorKey, HistoryContentKey,
    OverlayContentKey, StateContentKey,
};
pub use trin_types::execution::accumulator::{EpochAccumulator, HeaderRecord};
pub use trin_types::execution::block_body::BlockBody;
pub use trin_types::execution::header::HeaderWithProof;

// Re-exports jsonrpsee crate
pub use jsonrpsee;

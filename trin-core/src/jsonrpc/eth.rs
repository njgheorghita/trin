use std::sync::Arc;

use anyhow::anyhow;
use serde_json::{json, Number, Value};
use tokio::sync::{mpsc, RwLock};

use crate::{
    jsonrpc::{
        endpoints::HistoryEndpoint,
        handlers::proxy_query_to_history_subnet,
        types::{GetBlockByHashParams, GetBlockByNumberParams, HistoryJsonRpcRequest, Params},
    },
    portalnet::types::content_key::{BlockHeader, HistoryContentKey},
    types::header::Header,
    types::validation::{MERGE_BLOCK_NUMBER, HeaderOracle},
    utils::bytes::{hex_decode, hex_encode},
};

/// eth_getBlockByHash
pub async fn get_block_by_hash(
    params: Params,
    // change to header_oracle?
    // move this functionality to header oracle?
    history_jsonrpc_tx: &Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
) -> anyhow::Result<Value> {
    let params: GetBlockByHashParams = params.try_into()?;
    let content_key = HistoryContentKey::BlockHeader(BlockHeader {
        chain_id: 1,
        block_hash: params.block_hash,
    });
    let endpoint = HistoryEndpoint::RecursiveFindContent;
    let bytes_content_key: Vec<u8> = content_key.into();
    let hex_content_key = hex_encode(bytes_content_key);
    let overlay_params = Params::Array(vec![Value::String(hex_content_key)]);

    let resp = match history_jsonrpc_tx.as_ref() {
        Some(tx) => proxy_query_to_history_subnet(tx, endpoint, overlay_params).await,
        None => Err(anyhow!("Chain history subnetwork unavailable.")),
    };

    match resp {
        Ok(Value::String(val)) => hex_decode(val.as_str())
            .and_then(|bytes| {
                rlp::decode::<Header>(bytes.as_ref()).map_err(|_| anyhow!("Invalid RLP"))
            })
            .map(|header| json!(header)),
        Ok(Value::Null) => Ok(Value::Null),
        Ok(_) => Err(anyhow!("Invalid JSON value")),
        Err(err) => Err(err),
    }
}

/// eth_getBlockByNumber
pub async fn get_block_by_number(
    params: Params,
    header_oracle: Arc<RwLock<HeaderOracle>>
) -> anyhow::Result<Value> {
    let params: GetBlockByNumberParams = params.try_into()?;
    //let overlay_params = Params::Array(vec![Value::Number(Number::from(params.block_number))]);
    // if block_number > MERGE_BLOCK_NUMBER {
    // panic.
    // }
    let block_hash = header_oracle.read().get_hash_at_height(params.block_number)?;
    let params = GetBlockByHashParams {
        block_hash: block_hash.into(),
        full_transactions: params.full_transactions,
    };
    get_block_by_hash(params, header_oracle.history_jsonrpc_tx.clone()).await
}

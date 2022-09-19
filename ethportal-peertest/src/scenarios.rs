use std::{thread, time};

use serde_json::{json, Value};
use ssz::{Decode, Encode};
use tracing::{error, info};
use tree_hash::TreeHash;

use crate::{
    generate_trin_config,
    jsonrpc::{
        make_ipc_request, validate_portal_offer, JsonRpcRequest, HISTORY_CONTENT_KEY,
        HISTORY_CONTENT_VALUE,
    },
    launch_node, Peertest, PeertestConfig,
};
use trin_core::{
    jsonrpc::types::Params,
    portalnet::storage::PortalStorage,
    portalnet::types::content_key::{
        HistoryContentKey, MasterAccumulator as MasterAccumulatorKey, SszNone,
    },
    types::accumulator::{add_blocks_to_master_acc, MasterAccumulator},
    utils::bytes::{hex_decode, hex_encode},
};

pub fn test_offer_accept(peertest_config: PeertestConfig, peertest: &Peertest) {
    info!("Testing OFFER/ACCEPT flow");

    // Store content to offer in the testnode db
    let store_request = JsonRpcRequest {
        method: "portal_historyStore".to_string(),
        id: 11,
        params: Params::Array(vec![
            Value::String(HISTORY_CONTENT_KEY.to_string()),
            Value::String(HISTORY_CONTENT_VALUE.to_string()),
        ]),
    };

    let store_result = make_ipc_request(&peertest_config.target_ipc_path, &store_request).unwrap();
    assert_eq!(store_result.as_str().unwrap(), "true");

    // Send offer request from testnode to bootnode
    let offer_request = JsonRpcRequest {
        method: "portal_historySendOffer".to_string(),
        id: 11,
        params: Params::Array(vec![
            Value::String(peertest.bootnode.enr.to_base64()),
            Value::Array(vec![json!(HISTORY_CONTENT_KEY)]),
        ]),
    };

    let accept = make_ipc_request(&peertest_config.target_ipc_path, &offer_request).unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    validate_portal_offer(&accept, peertest);

    // Check if the stored content item in bootnode's DB matches the offered
    let local_content_request = JsonRpcRequest {
        method: "portal_historyLocalContent".to_string(),
        id: 16,
        params: Params::Array(vec![Value::String(HISTORY_CONTENT_KEY.to_string())]),
    };
    let mut received_content_value =
        make_ipc_request(&peertest.bootnode.web3_ipc_path, &local_content_request);
    while let Err(err) = received_content_value {
        error!("Retrying after 0.5sec, because content should have been present: {err}");
        thread::sleep(time::Duration::from_millis(500));
        received_content_value =
            make_ipc_request(&peertest.bootnode.web3_ipc_path, &local_content_request);
    }

    let received_content_value = match received_content_value {
        Ok(val) => val,
        Err(err) => {
            error!("Failed to find content that should be present: {err}");
            panic!("Could not get local content");
        }
    };

    let received_content_str = received_content_value.as_str().unwrap();
    assert_eq!(
        HISTORY_CONTENT_VALUE, received_content_str,
        "The received content {}, must match the expected {}",
        HISTORY_CONTENT_VALUE, received_content_str,
    );
}

// unwraps
pub async fn test_bootstrap_master_accumulator(
    _peertest_config: PeertestConfig,
    peertest: &Peertest,
) {
    info!("Testing Bootstrap Master Accumulator");
    let latest_acc_content_key: Vec<u8> =
        HistoryContentKey::MasterAccumulator(MasterAccumulatorKey::Latest(SszNone::new())).into();
    let latest_acc_content_key = hex_encode(latest_acc_content_key);

    // Validate that nodes are bootstrapped with trusted master acc by default.
    // Request latest master acc from bootnode
    let master_acc_request = JsonRpcRequest {
        method: "portal_historyLocalContent".to_string(),
        id: 11,
        params: Params::Array(vec![Value::String(latest_acc_content_key.clone())]),
    };
    let master_acc_response =
        make_ipc_request(&peertest.bootnode.web3_ipc_path, &master_acc_request).unwrap();
    let master_acc_response = hex_decode(master_acc_response.as_str().unwrap()).unwrap();
    let master_acc_response = MasterAccumulator::from_ssz_bytes(&master_acc_response).unwrap();
    // Load default master acc directly
    let default_master_acc = PortalStorage::default_trusted_master_acc();
    let default_master_acc = MasterAccumulator::from_ssz_bytes(&default_master_acc).unwrap();
    assert_eq!(master_acc_response, default_master_acc);

    // Validate that nodes can specify to use a specific master acc
    // generate a custom master acc
    let mut custom_master_acc = MasterAccumulator::default();
    add_blocks_to_master_acc(&mut custom_master_acc, 3);

    // Store custom master acc inside all nodes, with a master_hash content key (not "latest")
    let custom_master_acc_ssz = hex_encode(custom_master_acc.as_ssz_bytes());
    let master_hash_key: Vec<u8> = HistoryContentKey::MasterAccumulator(
        MasterAccumulatorKey::MasterHash(custom_master_acc.tree_hash_root()),
    )
    .into();
    let master_hash_key = hex_encode(master_hash_key);
    let store_request = JsonRpcRequest {
        method: "portal_historyStore".to_string(),
        id: 11,
        params: Params::Array(vec![
            Value::String(master_hash_key),
            Value::String(custom_master_acc_ssz),
        ]),
    };
    let store_result = make_ipc_request(&peertest.bootnode.web3_ipc_path, &store_request).unwrap();
    assert_eq!(store_result.as_str().unwrap(), "true");
    let store_result = make_ipc_request(&peertest.nodes[0].web3_ipc_path, &store_request).unwrap();
    assert_eq!(store_result.as_str().unwrap(), "true");

    // Bootstrap new node to bootstrap with custom master acc root hash
    let bootnode_enr = Some(&peertest.bootnode.enr);
    // use large id to avoid collisions
    let mut new_node_config = generate_trin_config(100, bootnode_enr);
    new_node_config.trusted_master_acc_hash = custom_master_acc.tree_hash_root();
    let new_node = launch_node(new_node_config).await.unwrap();

    // Validate that the custom master acc gets set as the new node's latest master acc
    let master_acc_request = JsonRpcRequest {
        method: "portal_historyLocalContent".to_string(),
        id: 11,
        params: Params::Array(vec![Value::String(latest_acc_content_key.to_string())]),
    };
    let master_acc_response =
        make_ipc_request(&new_node.web3_ipc_path, &master_acc_request).unwrap();
    let master_acc_response = hex_decode(master_acc_response.as_str().unwrap()).unwrap();
    let master_acc = MasterAccumulator::from_ssz_bytes(&master_acc_response).unwrap();
    assert_eq!(master_acc, custom_master_acc);

    // Handle exit for newly created node
    new_node.exiter.exit();
}

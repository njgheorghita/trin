use std::net::{IpAddr, Ipv4Addr};
use tokio::time::{sleep, Duration};

use tracing::info;

use crate::{
    utils::{fixture_header_with_proof, wait_for_history_content},
    Peertest,
};
use ethportal_api::{
    jsonrpsee::async_client::Client, types::cli::TrinConfig, Discv5ApiClient,
    HistoryNetworkApiClient, ContentValue, OverlayContentKey,
    utils::bytes::hex_encode,
};

pub async fn test_gossip_with_trace(peertest: &Peertest, target: &Client) {
    info!("Testing Gossip with tracing");

    let _ = target.ping(peertest.bootnode.enr.clone()).await.unwrap();
    let (content_key, content_value) = fixture_header_with_proof();
    let result = target
        .trace_gossip(content_key.clone(), content_value.clone())
        .await
        .unwrap();

    assert_eq!(result.offered.len(), 1);
    assert_eq!(result.accepted.len(), 1);
    assert_eq!(result.transferred.len(), 1);

    // Check if the stored content value in bootnode's DB matches the offered
    let received_content_value =
        wait_for_history_content(&peertest.bootnode.ipc_client, content_key.clone()).await;
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );

    // Spin up a fresh client, not connected to existing peertest
    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8899;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");
    let fresh_ipc_path = format!("/tmp/trin-jsonrpc-{test_discovery_port}.ipc");
    let trin_config = TrinConfig::new_from(
        [
            "trin",
            "--portal-subnetworks",
            "history,state",
            "--external-address",
            external_addr.as_str(),
            "--web3-ipc-path",
            fresh_ipc_path.as_str(),
            "--ephemeral",
            "--discovery-port",
            test_discovery_port.to_string().as_ref(),
            "--bootnodes",
            "none",
        ]
        .iter(),
    )
    .unwrap();

    let _test_client_rpc_handle = trin::run_trin(trin_config).await.unwrap();
    let fresh_target = reth_ipc::client::IpcClientBuilder::default()
        .build(fresh_ipc_path)
        .await
        .unwrap();
    let fresh_enr = fresh_target.node_info().await.unwrap().enr;

    // connect to new node
    let _ = target.ping(fresh_enr).await.unwrap();

    // send new trace gossip request
    let result = target
        .trace_gossip(content_key.clone(), content_value.clone())
        .await
        .unwrap();

    assert_eq!(result.offered.len(), 2);
    assert_eq!(result.accepted.len(), 1);
    assert_eq!(result.transferred.len(), 1);

    // Check if the stored content value in fresh node's DB matches the offered
    let received_content_value = wait_for_history_content(&fresh_target, content_key.clone()).await;
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );

    // test trace gossip without any expected accepts
    let result = target
        .trace_gossip(content_key, content_value)
        .await
        .unwrap();

    assert_eq!(result.offered.len(), 2);
    assert_eq!(result.accepted.len(), 0);
    assert_eq!(result.transferred.len(), 0);
}

pub async fn test_gossip_dropped(peertest: &Peertest, target: &Client) {
    info!("Testing Gossip with tracing");

    // connect target to network
    let _ = target.ping(peertest.bootnode.enr.clone()).await.unwrap();

    // Spin up a fresh client, not connected to existing peertest
    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8889;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");
    let fresh_ipc_path = format!("/tmp/trin-jsonrpc-{test_discovery_port}.ipc");
    let trin_config = TrinConfig::new_from(
        [
            "trin",
            "--portal-subnetworks",
            "history",
            "--external-address",
            external_addr.as_str(),
            "--mb",
            "1",
            "--web3-ipc-path",
            fresh_ipc_path.as_str(),
            "--ephemeral",
            "--discovery-port",
            test_discovery_port.to_string().as_ref(),
            "--bootnodes",
            "none",
            "--unsafe-private-key",
            // node id: 0x27128939ed60d6f4caef0374da15361a2c1cd6baa1a5bccebac1acd18f485900
            "0x9ca7889c09ef1162132251b6284bd48e64bd3e71d75ea33b959c37be0582a2fd",
        ]
        .iter(),
    )
    .unwrap();

    let _test_client_rpc_handle = trin::run_trin(trin_config).await.unwrap();
    let fresh_target = reth_ipc::client::IpcClientBuilder::default()
        .build(fresh_ipc_path)
        .await
        .unwrap();
    let fresh_enr = fresh_target.node_info().await.unwrap().enr;

    let mut stored_mbs = 0;
    println!("storing content 1");
    let epoch_acc = std::fs::read("test_assets/mainnet/0x030013c08b64bf7e3afab80ad4f8ea9423f1a7d8b31a149fc3b832d7980719c60c.portalcontent").unwrap();
    let epoch_acc_hash = ethportal_api::utils::bytes::hex_decode("0x0013c08b64bf7e3afab80ad4f8ea9423f1a7d8b31a149fc3b832d7980719c60c").unwrap();
    let content_key_1 = ethportal_api::HistoryContentKey::EpochAccumulator(ethportal_api::EpochAccumulatorKey {
        epoch_hash: alloy_primitives::B256::from_slice(&epoch_acc_hash).into(),
    });
    let content_value = ethportal_api::HistoryContentValue::decode(&epoch_acc).unwrap();
    let _ = target.ping(fresh_target.node_info().await.unwrap().enr.clone()).await.unwrap();
    sleep(Duration::from_secs(1)).await;
    //target.offer(fresh_enr.clone(), content_key_1.clone(), Some(content_value.clone())).await.unwrap();
    HistoryNetworkApiClient::store(&fresh_target, content_key_1.clone(), content_value.clone())
        .await
        .unwrap();
    stored_mbs += content_value.encode().len() as u64;
    sleep(Duration::from_secs(1)).await;

    assert!(HistoryNetworkApiClient::local_content(&fresh_target, content_key_1.clone())
        .await
        .is_ok());
    assert!(HistoryNetworkApiClient::local_content(target, content_key_1.clone())
        .await
        .is_err());



    println!("storing content 2");
    let epoch_acc = std::fs::read("test_assets/mainnet/0x03ed8823c84177d8ffabf104566f313a2b2a43d05304ba6c74c2f5555bae0ef329.portalcontent").unwrap();
    let epoch_acc_hash = ethportal_api::utils::bytes::hex_decode("0xed8823c84177d8ffabf104566f313a2b2a43d05304ba6c74c2f5555bae0ef329").unwrap();
    let content_key_2 = ethportal_api::HistoryContentKey::EpochAccumulator(ethportal_api::EpochAccumulatorKey {
        epoch_hash: alloy_primitives::B256::from_slice(&epoch_acc_hash).into(),
    });
    let content_value = ethportal_api::HistoryContentValue::decode(&epoch_acc).unwrap();
    target.offer(fresh_enr, content_key_2.clone(), Some(content_value.clone())).await.unwrap();
    //stored_mbs += content_value.encode().len() as u64;


    //println!("offering content 3");
    //let (content_key_3, content_value) = fixture_header_with_proof();
    //target.offer(fresh_enr, content_key_3.clone(), Some(content_value.clone())).await.unwrap();
    //stored_mbs += content_value.encode().len() as u64;
    
    // connect target to network
    // jk the offer should ping
    //let _ = target.ping(fresh_target.node_info().await.unwrap().enr.clone()).await.unwrap();
    println!("content id 1: {:?}", hex_encode(content_key_1.content_id()));
    //println!("content id 3: {:?}", hex_encode(content_key_3.content_id()));
    println!("content id 2: {:?}", hex_encode(content_key_2.content_id()));
    let target_enr = target.node_info().await.unwrap().enr.clone();
    println!("target enr: {:?}", target_enr.to_base64());
    sleep(Duration::from_secs(3)).await;


    println!("Stored {} MBs", stored_mbs);
    println!("Stored {} MBs", stored_mbs / 1024 / 1024);
    assert!(HistoryNetworkApiClient::local_content(&fresh_target, content_key_1.clone())
        .await
        .is_err());
    assert!(HistoryNetworkApiClient::local_content(&fresh_target, content_key_2.clone())
        .await
        .is_ok());
    assert!(HistoryNetworkApiClient::local_content(target, content_key_2.clone())
        .await
        .is_ok());
}

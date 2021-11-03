use std::io::prelude::*;
use std::os::unix::net::UnixStream;
use std::slice::Iter;

use hyper::{self, Body, Client, Method, Request};
use log::info;
use serde_json::{self, Value};
use thiserror::Error;

use trin_core::portalnet::U256;
use trin_core::jsonrpc::types::Params;
use super::cli::PeertestConfig;

#[derive(Clone)]
pub struct JsonRpcEndpoint {
    pub method: &'static str,
    pub id: &'static u8,
    pub params: Params,
}

fn validate_endpoint_response(method: &str, result: &Value) {
    match method {
        "web3_clientVersion" => {
            assert_eq!(result.as_str().unwrap(), "trin v0.1.0");
        }
        "discv5_nodeInfo" => {
            let enr = result.get("enr").unwrap();
            assert!(enr.is_string());
            assert!(enr.as_str().unwrap().contains("enr:"));
            assert!(result.get("nodeId").unwrap().is_string());
        }
        "discv5_routingTableInfo" => {
            let local_key = result.get("localKey").unwrap();
            assert!(local_key.is_string());
            assert!(local_key.as_str().unwrap().contains("0x"));
            assert!(result.get("buckets").unwrap().is_array());
        }
        "eth_blockNumber" => {
            assert!(result.is_string());
            assert!(result.as_str().unwrap().contains("0x"));
        }
        "portalHistory_dataRadius" => {
            assert_eq!(result.as_str().unwrap(), U256::from(u64::MAX).to_string());
        }
        "portalState_dataRadius" => {
            assert_eq!(result.as_str().unwrap(), U256::from(u64::MAX).to_string());
        }
        "portalHistory_ping" => {
            assert_eq!(result.as_str().unwrap(), U256::from(u64::MAX).to_string());
        }
        _ => panic!("Unsupported endpoint"),
    };
    info!("{:?} returned a valid response.", method);
}

impl JsonRpcEndpoint {
    pub fn all_endpoints(peertest_config: &PeertestConfig) -> Vec<JsonRpcEndpoint> {
        vec![
            JsonRpcEndpoint {
                method: "web3_clientVersion",
                id: &0,
                params: Params::None
            },
            JsonRpcEndpoint {
                method: "discv5_nodeInfo",
                id: &1,
                params: Params::None
            },
            JsonRpcEndpoint {
                method: "discv5_routingTableInfo",
                id: &2,
                params: Params::None
            },
            JsonRpcEndpoint {
                method: "eth_blockNumber",
                id: &3,
                params: Params::None
            },
            JsonRpcEndpoint {
                method: "portalHistory_dataRadius",
                id: &4,
                params: Params::None
            },
            JsonRpcEndpoint {
                method: "portalState_dataRadius",
                id: &5,
                params: Params::None
            },
            JsonRpcEndpoint {
                method: "portalHistory_ping",
                id: &6,
                params: Params::Array(vec![Value::String(peertest_config.target_node.clone())]),
            },
        ]
    }

    pub fn to_jsonrpc(self) -> String {
        match self.params {
            Params::None => format!(
                r#"
                {{
                    "jsonrpc":"2.0",
                    "id": {},
                    "method": "{}"
                }}"#,
                self.id, self.method
            ),
            _ => {
                let params = serde_json::to_string(&self.params).unwrap();
                format!(
                    r#"{{"jsonrpc":"2.0","id": {},"method": "{}","params": {}}}"#,
                    self.id, self.method, params
                )
            }
        }
    }
}

#[allow(clippy::never_loop)]
pub async fn test_jsonrpc_endpoints_over_ipc(peertest_config: PeertestConfig) {
    for endpoint in JsonRpcEndpoint::all_endpoints(&peertest_config) {
        let endpoint = endpoint.clone();
        info!("Testing over IPC: {:?}", endpoint.method);
        let mut stream = UnixStream::connect(&peertest_config.target_ipc_path).unwrap();
        let jsonrpc_request = &endpoint.clone().to_jsonrpc();
        let v: Value = serde_json::from_str(&jsonrpc_request).unwrap();
        let data = serde_json::to_vec(&v).unwrap();
        stream.write_all(&data).unwrap();
        stream.flush().unwrap();
        let deser = serde_json::Deserializer::from_reader(stream);
        for obj in deser.into_iter::<Value>() {
            let response_obj = obj.unwrap();
            match get_response_result(response_obj) {
                Ok(result) => validate_endpoint_response(endpoint.clone().method, &result),
                Err(msg) => panic!(
                    "Jsonrpc error for {:?} endpoint: {:?}",
                    &endpoint.method, msg
                ),
            }
            // break out of loop here since EOF is not sent, and loop will hang
            break;
        }
    }
}

#[derive(Error, Debug)]
pub enum JsonRpcResponseError {
    #[error("JsonRpc response contains an error: {0}")]
    Error(String),

    #[error("Invalid JsonRpc response")]
    Invalid(),
}

fn get_response_result(response: Value) -> Result<Value, JsonRpcResponseError> {
    println!("___");
    println!("{:?}", response);
    println!("___");
    match response.get("result") {
        Some(result) => Ok(result.clone()),
        None => match response.get("error") {
            Some(error) => Err(JsonRpcResponseError::Error(error.to_string())),
            None => Err(JsonRpcResponseError::Invalid()),
        },
    }
}

pub async fn test_jsonrpc_endpoints_over_http(peertest_config: PeertestConfig) {
    let client = Client::new();
    for endpoint in JsonRpcEndpoint::all_endpoints(&peertest_config) {
        info!("Testing over HTTP: {:?}", endpoint.method);
        let json_string = endpoint.clone().to_jsonrpc();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{}", &peertest_config.target_http_address))
            .header("content-type", "application/json")
            .body(Body::from(json_string))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let response_obj: Value = serde_json::from_slice(&body).unwrap();
        match get_response_result(response_obj) {
            Ok(result) => validate_endpoint_response(endpoint.method, &result),
            Err(msg) => panic!(
                "Jsonrpc error for {:?} endpoint: {:?}",
                endpoint.method, msg
            ),
        }
    }
}

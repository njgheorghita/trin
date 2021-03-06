//use web3::{Web3, transports};
use reqwest::blocking as reqwest;
use serde_json;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix;
use threadpool::ThreadPool;

// TODO: things to configure:
//  - infura project id (not just env var?)
//  - rpc endpoint port
//  - rpc endpoint type (tcp, ws, ipc)
//  - max concurrent requests (ie~ threadpool size)

pub fn launch_trin(infura_project_id: String) {
    println!("Launching with infura key: '{}'", infura_project_id);

    let pool = ThreadPool::new(2);

    let path = "/tmp/trin-jsonrpc.ipc";
    let listener_result = unix::net::UnixListener::bind(path);
    let listener = match listener_result {
        Ok(listener) => listener,
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            // TODO something smarter than just dropping the existing file and/or
            // make sure file gets cleaned up on shutdown.
            match fs::remove_file(path) {
                Err(_) => panic!("Could not serve from existing path '{}'", path),
                Ok(()) => unix::net::UnixListener::bind(path).unwrap(),
            }
        }
        Err(err) => {
            panic!("Could not serve from path '{}': {:?}", path, err);
        }
    };

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let infura_project_id = infura_project_id.clone();
        pool.execute(move || {
            let infura_url = format!("https://mainnet.infura.io:443/v3/{}", infura_project_id);
            let mut rx = stream.try_clone().unwrap();
            let mut tx = stream;
            serve_client(&mut rx, &mut tx, &infura_url);
        });
    }
}

fn serve_client(rx: &mut impl Read, tx: &mut impl Write, infura_url: &String) {
    println!("Welcoming...");
    let deser = serde_json::Deserializer::from_reader(rx);
    for obj in deser.into_iter::<serde_json::Value>() {
        let obj = obj.unwrap();
        assert!(obj.is_object());
        assert_eq!(obj["jsonrpc"], "2.0");
        let request_id = obj.get("id").unwrap();
        let method = obj.get("method").unwrap();

        let response = match method.as_str().unwrap() {
            "web3_clientVersion" => format!(
                r#"{{"jsonrpc":"2.0","id":{},"result":"trin 0.0.1-alpha"}}"#,
                request_id,
            )
            .into_bytes(),
            _ => {
                //Re-encode json to proxy to Infura
                let request = obj.to_string();
                match proxy_to_url(request, infura_url) {
                    Ok(result_body) => result_body,
                    Err(err) => format!(
                        r#"{{"jsonrpc":"2.0","id":"{}","error":"Infura failure: {}"}}"#,
                        request_id,
                        err.to_string(),
                    )
                    .into_bytes(),
                }
            }
        };
        tx.write_all(&response).unwrap();
    }
    println!("Clean exit");
}

fn proxy_to_url(request: String, url: &String) -> io::Result<Vec<u8>> {
    let client = reqwest::Client::new();
    match client.post(url).body(request).send() {
        Ok(response) => {
            let status = response.status();

            if status.is_success() {
                match response.bytes() {
                    Ok(bytes) => Ok(bytes.to_vec()),
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Unexpected error when accessing the response body",
                    )),
                }
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Responded with status code: {:?}", status),
                ))
            }
        }
        Err(err) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Request failure: {:?}", err),
        )),
    }
}

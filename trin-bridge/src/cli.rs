use crate::types::NetworkKind;
use anyhow::bail;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;
use tokio::process::{Child, Command};
use url::Url;

// max value of 16 b/c...
// - reliably calculate spaced private keys in a reasonable time
// - for values b/w 16 - 256, calculated spaced private keys are
//   less and less evenly spread
// - running more than 16 trin nodes simultaneously is not thoroughly tested
pub const MAX_NODE_COUNT: u8 = 16;
const DEFAULT_SUBNETWORK: &str = "history";

#[derive(Parser, Debug, PartialEq, Clone)]
#[command(name = "Trin Bridge", about = "Feed the network")]
pub struct BridgeConfig {
    #[arg(
        long,
        help = "number of trin nodes to launch - must be between 1 and 16",
        //default_value = "1",
        value_parser = check_node_count
    )]
    pub node_count: u8,

    #[arg(long, help = "path to portalnet client executable")]
    pub executable_path: PathBuf,

    #[arg(
        long,
        default_value = "latest",
        help = "['latest', 'backfill', <u64> to provide the starting epoch]"
    )]
    pub mode: BridgeMode,

    #[arg(
        long = "epoch-accumulator-path",
        help = "Path to epoch accumulator repo for bridge mode"
    )]
    pub epoch_acc_path: PathBuf,

    #[arg(
        long = "network",
        help = "Comma-separated list of which portal subnetworks to activate",
        default_value = DEFAULT_SUBNETWORK,
        use_value_delimiter = true
    )]
    pub network: Vec<NetworkKind>,

    #[arg(long, help = "Url for metrics reporting")]
    pub metrics_url: Option<Url>,

    #[command(subcommand)]
    pub client_type: ClientType,
}

fn check_node_count(val: &str) -> Result<u8, String> {
    let node_count: u8 = val.parse().map_err(|_| "Invalid node count".to_string())?;
    if node_count > 0 && node_count <= MAX_NODE_COUNT {
        Ok(node_count)
    } else {
        Err(format!("Node count must be between 1 and {MAX_NODE_COUNT}"))
    }
}

/// Used to help decode cli args identifying the desired bridge mode.
/// - Latest: tracks the latest header
/// - Backfill: starts at block 0
/// - StartFromEpoch: starts at the given epoch
///   - ex: "e123" starts at epoch 123
/// - Single: executes a single block
///   - ex: "b123" executes block 123
#[derive(Clone, Debug, PartialEq, Default, Eq)]
pub enum BridgeMode {
    #[default]
    Latest,
    Backfill(ModeType),
    Single(ModeType),
    Test(PathBuf),
}
// latest - none
// start-epoch - u64
// --mode start:e134
// --mode single:b0
// --mode test:file_path
// --mode latest
// start-block - u64
// single-epoch - u64
// single-block - u64
// test - file path
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModeType {
    Epoch(u64),
    Block(u64),
}

type ParseError = &'static str;

impl FromStr for BridgeMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest" => Ok(BridgeMode::Latest),
            val => match &val[..1] {
                "e" => {
                    let epoch = val[1..]
                        .parse()
                        .map_err(|_| "Invalid bridge mode arg: epoch number")?;
                    Ok(BridgeMode::Backfill(ModeType::Epoch(epoch)))
                }
                "b" => {
                    let block = val[1..]
                        .parse()
                        .map_err(|_| "Invalid bridge mode arg: block number")?;
                    Ok(BridgeMode::Single(ModeType::Block(block)))
                }
                _ => Err("Invalid bridge mode arg: type prefix"),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Subcommand)]
pub enum ClientType {
    Fluffy,
    Trin,
}

impl FromStr for ClientType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "fluffy" => Ok(ClientType::Fluffy),
            "trin" => Ok(ClientType::Trin),
            _ => Err("Invalid client type"),
        }
    }
}

impl ClientType {
    pub fn build_handle(
        &self,
        private_key: String,
        rpc_port: u64,
        udp_port: u64,
        bridge_config: BridgeConfig,
    ) -> anyhow::Result<Child> {
        match self {
            ClientType::Fluffy => fluffy_handle(private_key, rpc_port, udp_port, bridge_config),
            ClientType::Trin => trin_handle(private_key, rpc_port, udp_port, bridge_config),
        }
    }
}

fn fluffy_handle(
    private_key: String,
    rpc_port: u64,
    udp_port: u64,
    bridge_config: BridgeConfig,
) -> anyhow::Result<Child> {
    let mut command = Command::new(bridge_config.executable_path);
    command
        .kill_on_drop(true)
        .arg("--storage-size:0")
        .arg("--rpc")
        .arg(format!("--rpc-port:{rpc_port}"))
        .arg(format!("--udp-port:{udp_port}"))
        .arg("--network:testnet0")
        .arg("--table-ip-limit:1024")
        .arg("--bucket-ip-limit:24")
        .arg(format!("--netkey-unsafe:{private_key}"));
    if let Some(metrics_url) = bridge_config.metrics_url {
        let address = match metrics_url.host_str() {
            Some(address) => address,
            None => bail!("Invalid metrics url address"),
        };
        let port = match metrics_url.port() {
            Some(port) => port,
            None => bail!("Invalid metrics url port"),
        };
        command
            .arg("--metrics")
            .arg(format!("--metrics-address:{address}"))
            .arg(format!("--metrics-port:{port}"));
    }
    Ok(command.spawn()?)
}

fn trin_handle(
    private_key: String,
    rpc_port: u64,
    udp_port: u64,
    bridge_config: BridgeConfig,
) -> anyhow::Result<Child> {
    let mut command = Command::new(bridge_config.executable_path);
    let epoch_acc_path: String = format!("{}", bridge_config.epoch_acc_path.display());
    command
        .kill_on_drop(true)
        .args(["--ephemeral"])
        .args(["--mb", "0"])
        .args(["--web3-transport", "http"])
        .args(["--unsafe-private-key", &private_key])
        .args([
            "--web3-http-address",
            &format!("http://127.0.0.1:{rpc_port}"),
        ])
        .args(["--discovery-port", &format!("{udp_port}")])
        .args(["--epoch-accumulator-path", &epoch_acc_path])
        .args(["--bootnodes", "default"]);
    if let Some(metrics_url) = bridge_config.metrics_url {
        let url: String = metrics_url.into();
        command.args(["--enable-metrics-with-url", &url]);
    }
    Ok(command.spawn()?)
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[test]
    fn test_default_bridge_config() {
        const NODE_COUNT: &str = "1";
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        let bridge_config = BridgeConfig::parse_from([
            "bridge",
            "--node-count",
            NODE_COUNT,
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
            "--network",
            "history,beacon",
            "trin",
        ]);
        assert_eq!(bridge_config.node_count, 1);
        assert_eq!(
            bridge_config.executable_path,
            PathBuf::from(EXECUTABLE_PATH)
        );
        assert_eq!(bridge_config.mode, BridgeMode::Latest);
        assert_eq!(bridge_config.epoch_acc_path, PathBuf::from(EPOCH_ACC_PATH));
        assert_eq!(
            bridge_config.network,
            vec![NetworkKind::History, NetworkKind::Beacon]
        );
    }

    #[test]
    fn test_bridge_config_with_epoch() {
        const NODE_COUNT: &str = "1";
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        const EPOCH: &str = "e100";
        let bridge_config = BridgeConfig::parse_from([
            "bridge",
            "--node-count",
            NODE_COUNT,
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
            "--mode",
            EPOCH,
            "trin",
        ]);
        assert_eq!(bridge_config.node_count, 1);
        assert_eq!(
            bridge_config.executable_path,
            PathBuf::from(EXECUTABLE_PATH)
        );
        assert_eq!(
            bridge_config.mode,
            BridgeMode::Backfill(ModeType::Epoch(100))
        );
        assert_eq!(bridge_config.epoch_acc_path, PathBuf::from(EPOCH_ACC_PATH));
        assert_eq!(bridge_config.network, vec![NetworkKind::History]);
    }

    #[test]
    fn test_bridge_config_with_max_node_count() {
        let node_count_string = MAX_NODE_COUNT.to_string();
        let node_count: &str = node_count_string.as_str();
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        let bridge_config = BridgeConfig::parse_from([
            "bridge",
            "--node-count",
            node_count,
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
            "trin",
        ]);
        assert_eq!(bridge_config.node_count, 16);
        assert_eq!(
            bridge_config.executable_path,
            PathBuf::from(EXECUTABLE_PATH)
        );
        assert_eq!(bridge_config.mode, BridgeMode::Latest);
        assert_eq!(bridge_config.epoch_acc_path, PathBuf::from(EPOCH_ACC_PATH));
        assert_eq!(bridge_config.network, vec![NetworkKind::History]);
    }

    #[test]
    #[should_panic(
        expected = "Invalid network arg. Expected either 'beacon', 'history' or 'state'"
    )]
    fn test_invalid_network_arg() {
        BridgeConfig::try_parse_from(["bridge", "--network", "das", "trin"].iter()).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingSubcommand")]
    fn test_config_requires_client_type_subcommand() {
        BridgeConfig::try_parse_from([
            "bridge",
            "--node-count",
            "1",
            "--executable-path",
            "path/to/executable",
            "--epoch-accumulator-path",
            "path/to/epoch/accumulator",
        ])
        .unwrap();
    }

    #[rstest]
    #[case("latest", BridgeMode::Latest)]
    fn test_mode_flag(#[case] actual: String, #[case] expected: BridgeMode) {
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        let bridge_config = BridgeConfig::parse_from([
            "bridge",
            "--node-count",
            "1",
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
            "--mode",
            &actual,
        ]);
        assert_eq!(bridge_config.mode, expected);
    }
}

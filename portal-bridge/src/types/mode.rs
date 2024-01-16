use std::{ops::Range, path::PathBuf, str::FromStr};

use trin_validation::constants::EPOCH_SIZE;

/// Used to help decode cli args identifying the desired bridge mode.
/// - Latest: tracks the latest header
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
    Range(Range<u64>),
}

type ParseError = &'static str;

impl FromStr for BridgeMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest" => Ok(BridgeMode::Latest),
            val => {
                let index = val
                    .find(':')
                    .ok_or("Invalid bridge mode arg: missing ':'")?;
                let (mode, val) = val.split_at(index);
                match mode {
                    "backfill" => {
                        let mode_type = ModeType::from_str(&val[1..])?;
                        Ok(BridgeMode::Backfill(mode_type))
                    }
                    "single" => {
                        let mode_type = ModeType::from_str(&val[1..])?;
                        Ok(BridgeMode::Single(mode_type))
                    }
                    "test" => {
                        let path =
                            PathBuf::from_str(&val[1..]).map_err(|_| "Invalid test asset path")?;
                        Ok(BridgeMode::Test(path))
                    }
                    "range" => {
                        let mut range = val[1..]
                            .split('-')
                            .map(|s| s.parse::<u64>())
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|_| {
                                "Invalid range: expected two integers connected with a -"
                            })?;
                        if range.len() != 2 {
                            return Err("Invalid range: invalid amount of integers");
                        }
                        let start = range.remove(0);
                        let end = range.remove(0);
                        if start >= end {
                            return Err("Invalid range: start is >= end. For a single block use `single` mode.");
                        }
                        Ok(BridgeMode::Range(start..end))
                    }
                    _ => Err("Invalid bridge mode arg: type prefix"),
                }
            }
        }
    }
}

impl BridgeMode {
    // docstring
    pub fn validate_against_latest(&self, latest: u64) -> Result<(), String> {
        match self {
            BridgeMode::Latest => Ok(()),
            BridgeMode::Test(_) => Ok(()),
            BridgeMode::Single(mode_type) => mode_type.validate_against_latest(latest),
            BridgeMode::Backfill(mode_type) => mode_type.validate_against_latest(latest),
            BridgeMode::Range(range) => {
                if range.end > latest {
                    return Err(format!(
                        "Invalid bridge mode arg: range end {} is greater than latest {}",
                        range.end, latest
                    ));
                }
                Ok(())
            }
        }
    }
}

impl ModeType {
    fn validate_against_latest(&self, latest: u64) -> Result<(), String> {
        match self {
            ModeType::Epoch(epoch) => {
                if *epoch * EPOCH_SIZE as u64 > latest {
                    return Err(format!(
                        "Invalid bridge mode arg: epoch {epoch} contains block that is greater than latest {latest}",
                    ));
                }
            }
            ModeType::Block(block) => {
                if *block > latest {
                    return Err(format!(
                        "Invalid bridge mode arg: block {block} is greater than latest {latest}",
                    ));
                }
            }
            ModeType::Range(_) => return Err("Invalid bridge mode arg: range is not a supported ModeType. Use `range:` selector instead.".to_string()),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModeType {
    Epoch(u64),
    Block(u64),
    Range(Range<u64>),
}

impl FromStr for ModeType {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "e" => {
                let epoch = s[1..]
                    .parse()
                    .map_err(|_| "Invalid bridge mode arg: epoch number")?;
                Ok(ModeType::Epoch(epoch))
            }
            "b" => {
                let block = s[1..]
                    .parse()
                    .map_err(|_| "Invalid bridge mode arg: block number")?;
                Ok(ModeType::Block(block))
            }
            // "r" (Range) is not a supported ModeType in the cli, but used internally.
            // Users can use the `range:` prefix to specify a range of blocks. It doesn't
            // make sense to support a backfill / single cli option for a range of blocks.
            _ => Err("Invalid bridge mode arg: type prefix"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cli::BridgeConfig;
    use clap::Parser;
    use rstest::rstest;

    #[rstest]
    #[case("latest", BridgeMode::Latest)]
    #[case("single:b0", BridgeMode::Single(ModeType::Block(0)))]
    #[case("single:b1000", BridgeMode::Single(ModeType::Block(1000)))]
    #[case("single:e0", BridgeMode::Single(ModeType::Epoch(0)))]
    #[case("single:e1000", BridgeMode::Single(ModeType::Epoch(1000)))]
    #[case("backfill:b0", BridgeMode::Backfill(ModeType::Block(0)))]
    #[case("backfill:b1000", BridgeMode::Backfill(ModeType::Block(1000)))]
    #[case("backfill:e0", BridgeMode::Backfill(ModeType::Epoch(0)))]
    #[case("backfill:e1000", BridgeMode::Backfill(ModeType::Epoch(1000)))]
    #[case("range:0-100", BridgeMode::Backfill(ModeType::Epoch(1000)))]
    #[case("range:10000-100000", BridgeMode::Backfill(ModeType::Epoch(1000)))]
    #[case(
        "test:/usr/eth/test.json",
        BridgeMode::Test(PathBuf::from("/usr/eth/test.json"))
    )]
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
            "trin",
        ]);
        assert_eq!(bridge_config.mode, expected);
    }

    #[rstest]
    #[case("xxx")]
    #[case("single:0")]
    #[case("backfill:0")]
    #[case("backfill:100-101")]
    #[case("range:xxx")]
    #[case("range:100")]
    #[case("range:100-0")]
    #[case("range:100-100")]
    fn test_invalid_modes(#[case] mode: &str) {
        let mode = BridgeMode::from_str(mode);
        assert!(mode.is_err());
    }
}

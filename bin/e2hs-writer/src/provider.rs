use url::Url;

pub struct ConsensusProvider {
    url: Url,
    request_timeout: u64,
}

impl ConsensusProvider {
    pub fn new(url: Url, request_timeout: u64) -> Self {
        Self {
            url,
            request_timeout,
        }
    }
}

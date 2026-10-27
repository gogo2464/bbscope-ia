use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("unexpected HTTP status {status} from {url}")]
    Status { status: u16, url: String },

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("you are temporarily WAF banned, change IP or wait a few hours")]
    WafBanned,

    #[error("invalid response: {0}")]
    InvalidResponse(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
}

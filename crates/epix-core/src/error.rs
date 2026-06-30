//! The crate-wide error type.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("crypto: {0}")]
    Crypt(String),

    #[error("invalid peer address: {0}")]
    InvalidPeer(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("database: {0}")]
    Db(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

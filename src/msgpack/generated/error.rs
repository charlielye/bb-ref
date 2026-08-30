//! Error types for generated IPC clients.
//!
//! Mirrors `ipc-codegen/templates/rust/error.rs` without the `thiserror` dependency (the only
//! template consumer in this crate), so the generated client and server compile against the same
//! API with hand-written `Display`/`Error` impls.

#[derive(Debug)]
pub enum IpcError {
    Serialization(String),
    Deserialization(String),
    Backend(String),
    Ipc(String),
    Io(std::io::Error),
    InvalidResponse(String),
    Connection(String),
    Wasm(String),
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcError::Serialization(s) => write!(f, "Serialization error: {s}"),
            IpcError::Deserialization(s) => write!(f, "Deserialization error: {s}"),
            IpcError::Backend(s) => write!(f, "Backend error: {s}"),
            IpcError::Ipc(s) => write!(f, "IPC error: {s}"),
            IpcError::Io(e) => write!(f, "IO error: {e}"),
            IpcError::InvalidResponse(s) => write!(f, "Invalid response: {s}"),
            IpcError::Connection(s) => write!(f, "Connection error: {s}"),
            IpcError::Wasm(s) => write!(f, "WASM error: {s}"),
        }
    }
}

impl std::error::Error for IpcError {}

impl From<std::io::Error> for IpcError {
    fn from(e: std::io::Error) -> Self {
        IpcError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, IpcError>;

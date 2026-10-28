use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{op}: {source}")]
    Errno {
        op: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{0} is not available on this platform")]
    Unsupported(&'static str),
}

impl Error {
    pub fn from_io(op: &'static str, source: io::Error) -> Self {
        Self::Errno { op, source }
    }

    pub fn last(op: &'static str) -> Self {
        Self::from_io(op, io::Error::last_os_error())
    }

    pub fn raw_os_error(&self) -> Option<i32> {
        match self {
            Self::Errno { source, .. } => source.raw_os_error(),
            Self::Unsupported(_) => None,
        }
    }
}

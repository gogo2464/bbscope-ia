//! Bug bounty platform clients.
//!
//! Each platform lives in its own module behind a cargo feature of the same
//! name and implements [`bbscope_core::Platform`]. Adding a platform means
//! adding a module here; nothing else in the workspace needs to change
//! except the CLI wiring.

#[cfg(feature = "bugcrowd")]
pub mod bugcrowd;
#[cfg(feature = "hackerone")]
pub mod hackerone;
#[cfg(feature = "immunefi")]
pub mod immunefi;
#[cfg(feature = "intigriti")]
pub mod intigriti;
#[cfg(feature = "yeswehack")]
pub mod yeswehack;

mod util;

pub use bbscope_core::{Platform, PollOptions};

/// Credentials shared by the login-based platforms.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub email: String,
    pub password: String,
    pub otp_secret: String,
}

impl Credentials {
    pub fn is_complete(&self) -> bool {
        !self.email.is_empty() && !self.password.is_empty() && !self.otp_secret.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.email.is_empty() && self.password.is_empty() && self.otp_secret.is_empty()
    }
}

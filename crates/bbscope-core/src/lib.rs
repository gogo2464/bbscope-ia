//! Core building blocks shared by every bbscope crate.
//!
//! - [`model`]: scope data types (programs, scope elements, stored entries, changes)
//! - [`category`]: mapping raw platform categories to unified ones
//! - [`normalize`]: target / URL / domain normalization helpers
//! - [`http`]: a small retrying HTTP client used by all platforms
//! - [`output`]: `-o tdcu` style line formatting
//! - [`otp`]: TOTP generation for 2FA logins
//! - [`platform`]: the [`Platform`] trait every bug bounty platform implements

pub mod category;
pub mod error;
pub mod http;
pub mod json;
pub mod model;
pub mod normalize;
pub mod otp;
pub mod output;
pub mod platform;

pub use error::{Error, Result};
pub use model::*;
pub use http::{HttpClient, HttpConfig, Request, Response};
pub use platform::{Platform, PollOptions};

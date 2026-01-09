//! HTTP protocol adapter module.
//!
//! This module provides HTTP-specific implementations of protocol-agnostic traits.

pub mod http_response_builder;

pub use http_response_builder::HttpResponseBuilder;

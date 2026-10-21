//! Traceroute tools designed for internet measurements.
//
// This work is conducted at Carnegie Mellon University
// SPDX-License-Identifier: Apache-2.0

#![feature(const_trait_impl)]
#![feature(const_convert)]
#![feature(duration_millis_float)]
#![deny(rust_2018_idioms, missing_debug_implementations)]
#![deny(clippy::pedantic, clippy::cargo, clippy::nursery, clippy::unwrap_used)]
#![deny(clippy::allow_attributes_without_reason, clippy::allow_attributes)]

pub mod outputs;
pub mod time;
pub mod tracers;

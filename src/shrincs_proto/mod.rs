//! Experimental SHRINCS prototype scaffolding.
//!
//! This module sketches the stateful + stateless hybrid described
//! in the SHRINCS proposal (ePrint 2025/2203; Delving thread Dec 11 2025).
//! It is **not** wired into consensus and remains stub-only for future work.

#![allow(dead_code)]

pub mod fors;
pub mod hybrid;
pub mod wots_c;
pub mod xmss_unbalanced;

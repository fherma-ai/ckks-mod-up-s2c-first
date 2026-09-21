//! ENVELOPE — the specification's side of the measurement, laid over every
//! submission: what turns the point into a context, a case into the stage's
//! input, the output into bytes, and the output into a verdict's metrics.
//! Four functions and three types; the loop (`main.rs`, generated from the
//! signature) calls them around the author's `init` / `run` / `free`.
//!
//! The substance is in the submodules: `keys` (setup — the same keygen as the
//! bootstrapping's), `case` (generate: the message encrypted, then the
//! reference SlotsToCoeffs), `bytes` (the canonical serialisation), `check`
//! (the form of the raised ciphertext), `backend` (which Poulpy backend, by
//! cargo feature).

pub mod backend;
pub mod bytes;
pub mod case;
pub mod check;
pub mod keys;

use crate::fherma::{Inputs, Point};

pub use case::Case;
pub use keys::{Context, Ct};

/// Discarded runs before the first timed one.
pub const WARMUP: usize = 3;

/// What `run` receives: the ciphertext SlotsToCoeffs left, at 48 bits, with
/// the message beside it.
pub type Input = Case;

/// What `run` leaves: the raised ciphertext, at the bootstrap width — the
/// signature's `ct`.
pub type Output = Ct;

/// What `check` says of an output.
pub struct Check {
    pub valid: bool,
    pub metrics: Vec<(&'static str, f64)>,
    pub note: Option<String>,
}

/// The context from the point: keygen from `key_seed`, once. Not measured.
/// The worker pool of a `*-rayon` backend is sized here, from the solution's
/// `config.jsonc` (`threads`; 0 or absent is every core): it is built once
/// per process, before any work, and keygen is work.
pub fn setup(point: &Point, config: &str) -> Context {
    if backend::THREADED {
        backend::set_threads(threads(config));
    }
    Context::setup(point)
}

/// `threads` from `config.jsonc`; 0 or absent is every core.
fn threads(config: &str) -> usize {
    let all = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let text: String = config
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    text.find("\"threads\"")
        .and_then(|at| text[at..].find(':').map(|colon| at + colon + 1))
        .and_then(|from| {
            let rest = text[from..].trim_start();
            let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            rest[..end].parse::<usize>().ok()
        })
        .filter(|&t| t > 0)
        .unwrap_or(all)
}

/// Facts about the context, for the report's header.
pub fn describe(context: &Context) -> Vec<(&'static str, String)> {
    vec![
        ("preset", context.preset.name().to_string()),
        ("poulpy", keys::POULPY_VERSION.to_string()),
        ("backend", backend::NAME.to_string()),
    ]
}

/// The case from its inputs: the message encrypted, then SlotsToCoeffs. Not measured.
pub fn generate(context: &Context, inputs: &Inputs) -> Input {
    case::generate(context, inputs)
}

/// The output as the bytes the platform hashes: one entry, the signature's `ct`.
pub fn serialize(output: &Output) -> Vec<(&'static str, Vec<u8>)> {
    vec![("ct", bytes::bytes(output))]
}

/// Whether the output has the form the raise leaves: the input's ring, slots
/// and sparsity, the full bootstrap width, and the scale the S2C-first raise
/// stamps — the input's modulus plus the CoeffsToSlots guard bits.
pub fn check(context: &Context, input: &Input, output: &Output) -> Check {
    use poulpy_ckks::CKKSInfos;
    use poulpy_core::layouts::{GLWEInfos, LWEInfos};

    let expected_log_delta = input.ct.k().as_usize() + context.context.c2s_guard_bits();
    let shaped = output.n() == input.ct.n()
        && output.rank() == input.ct.rank()
        && output.base2k() == input.ct.base2k()
        && output.slots() == input.ct.slots()
        && output.log_sparsity() == input.ct.log_sparsity()
        && output.k().as_usize() == context.preset.bootstrap_k()
        && output.log_delta() == expected_log_delta;
    Check {
        valid: shaped,
        metrics: vec![
            ("k_bits", output.k().as_usize() as f64),
            ("log_delta", output.log_delta() as f64),
            ("mean_magnitude", check::mean_magnitude(context, output)),
        ],
        note: None,
    }
}

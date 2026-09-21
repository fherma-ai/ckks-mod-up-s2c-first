//! CHECK — what the output is, beside the digest. NOT measured as score;
//! timed apart and reported as metrics.
//!
//! Correctness on the platform is the digest. A ModUp changes no
//! coefficient's residue: it rewrites the ciphertext at a wider modulus, so
//! that each coefficient `c` becomes `c + I·q` for an integer `I`, with `q`
//! the modulus it came from — exactly what EvalMod removes next. What is
//! read here is the form: the width the raise reached and the scale it
//! stamped. The coefficients themselves are reported as a mean magnitude,
//! for the record. The specification's file; it has the secret because
//! `setup` does.

use poulpy_ckks::api::CKKSDecryptOps;
use poulpy_ckks::layouts::{CKKSModuleAlloc, CKKSPlaintextVecHostCodec};
use poulpy_ckks::{CKKSInfos, CKKSMeta, SetCKKSInfos, SlotsKind};
use poulpy_core::layouts::LWEInfos;
use poulpy_hal::api::ScratchOwnedBorrow;

use super::keys::{Context, Ct};

/// Plaintext budget bits above `log_delta` a ciphertext is decrypted at, as
/// in Poulpy's driver.
const LOG_BUDGET: usize = 8;

/// The mean absolute value of the output's coefficients at its scale: the
/// integer parts `I·q` are in there, so this is of the order of the sparse
/// secret's Hamming weight, not of the message.
pub fn mean_magnitude(state: &Context, output: &Ct) -> f64 {
    let coeffs = coefficients(state, output);
    coeffs.iter().map(|c| c.abs()).sum::<f64>() / coeffs.len().max(1) as f64
}

/// The coefficients a ciphertext encrypts, as floats at its scale.
pub fn coefficients(state: &Context, ct: &Ct) -> Vec<f64> {
    let log_delta = ct.log_delta();
    let log_budget = ct
        .log_budget()
        .min(LOG_BUDGET)
        .min(127usize.saturating_sub(log_delta));
    let mut pt = state
        .module
        .ckks_pt_vec_alloc(ct.base2k(), (log_delta + log_budget).into());
    pt.set_meta(CKKSMeta {
        log_sparsity: 0,
        log_delta,
        slots: SlotsKind::Complex,
    });
    let mut arena = state.scratch.borrow_mut();
    state
        .module
        .ckks_decrypt(&mut pt, ct, &state.sk, &mut arena.borrow())
        .expect("decrypt for the precision check");
    let mut coeffs = vec![0f64; ct.n().as_usize()];
    pt.decode_host_floats(&mut coeffs)
        .expect("read the coefficients for the precision check");
    coeffs
}


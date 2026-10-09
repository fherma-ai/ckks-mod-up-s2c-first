//! GENERATE — one test case from its seed. NOT measured.
//!
//! The stage's input is the ciphertext ModUp receives inside a bootstrap: the
//! bootstrap's own input taken through SlotsToCoeffs. The message, its
//! encryption mask and error are all derived from the case's seed, so a case
//! is its seed; SlotsToCoeffs is run by the reference code below, byte for
//! byte what `ckks_bootstrap` does first. The specification's file, laid over
//! every submission.

use poulpy_ckks::api::{CKKSCopyOps, CKKSDFTOps, CKKSEncodingHostOps, CKKSEncryptOps, CKKSPow2Ops};
use poulpy_ckks::layouts::{BootstrappingKeys, CKKSModuleAlloc};
use poulpy_ckks::{CKKSInfos, SetCKKSInfos};
use poulpy_core::layouts::LWEInfos;
use poulpy_hal::api::ScratchOwnedBorrow;
use poulpy_hal::source::Source;

use crate::fherma::Inputs;

use super::keys::{seed32, Context, Ct};

/// One test case: the stage's input — the ciphertext SlotsToCoeffs left,
/// whose coefficients hold the message.
pub struct Case {
    pub ct: Ct,
}

/// One test case from its input — the signature's `Inputs`, one seed: the
/// message encrypted at the preset's input layout, then the reference
/// SlotsToCoeffs.
pub fn generate(state: &Context, input: &Inputs) -> Case {
    let (re, im) = sample_unit_disc(input.case_seed, state.preset.n() / 2);
    let fresh = encrypt_message(state, input.case_seed, &re, &im);
    Case { ct: slots_to_coeffs(state, &fresh) }
}

/// The message as given, encoded and encrypted with the seed's mask and error.
pub fn encrypt_message(state: &Context, seed: u64, re: &[f64], im: &[f64]) -> Ct {
    let mut pt = state
        .module
        .ckks_pt_vec_alloc(state.preset.base2k().into(), state.input_layout.k());
    pt.set_meta(state.input_layout.meta());
    let mut arena = state.scratch.borrow_mut();
    state
        .module
        .ckks_encode_reim_into(&mut pt, re, im, &mut arena.borrow())
        .expect("encode the case message");

    // 0.9.0 samples the mask and the Gaussian noise at the ciphertext's own
    // width, so the encryption layout is no longer the caller's to pass.
    let mut ct = state.module.ckks_ciphertext_alloc_from_glwe_infos(&state.input_layout);
    let mut xa = Source::new(seed32(seed, "input-xa"));
    let mut xe = Source::new(seed32(seed, "input-xe"));
    state
        .module
        .ckks_encrypt_sk(
            &mut ct,
            &pt,
            &state.sk,
            &mut xe,
            &mut xa,
            &mut arena.borrow(),
        )
        .expect("encrypt the case input");
    ct
}

/// Stage 1 of the S2C-first pipeline: the slots to the coefficients. A copy
/// doubled first — the split decode matrix reconstructs `2·ct`, and the
/// orchestrator keeps that normalisation — then the homomorphic decode DFT.
pub fn slots_to_coeffs(state: &Context, fresh: &Ct) -> Ct {
    let mut ct = state.module.ckks_ciphertext_alloc_from_glwe_infos(&state.input_layout);
    let mut arena = state.scratch.borrow_mut();
    let mut scratch = arena.borrow();
    state.module.ckks_copy(&mut ct, fresh, &mut scratch).expect("copy the input");
    state
        .module
        .ckks_mul_pow2_assign(&mut ct, 1, &mut scratch)
        .expect("double the input");
    state
        .module
        .ckks_dft_evaluate_assign(
            &mut ct,
            state.context.slots_to_coeffs(),
            state.keys.rotation_keys(),
            &mut scratch,
        )
        .expect("SlotsToCoeffs");
    ct
}

/// `m` complex values uniform on the unit disc, from the case-seed: SplitMix64
/// over a per-case root, points drawn uniformly in the square and kept when
/// inside the disc. Only multiplication and comparison — no libm, so the same
/// seed gives the same f64 message bit-for-bit on any platform.
pub fn sample_unit_disc(seed: u64, m: usize) -> (Vec<f64>, Vec<f64>) {
    let mut state = u64::from_le_bytes(seed32(seed, "msg")[..8].try_into().unwrap());
    let mut next = || -> f64 {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 52) as f64 - 1.0 // in [-1, 1)
    };
    let (mut re, mut im) = (Vec::with_capacity(m), Vec::with_capacity(m));
    while re.len() < m {
        let (x, y) = (next(), next());
        if x * x + y * y < 1.0 {
            re.push(x);
            im.push(y);
        }
    }
    (re, im)
}

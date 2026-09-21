//! RUN — the function under measurement. The loop times this call and
//! nothing else.
//!
//! Reference: Poulpy's ModUp as the S2C-first bootstrap performs it
//! (`ckks_bootstrap_s2c_mod_up` in Poulpy, after its SlotsToCoeffs): the
//! encapsulated raise — a key switch to the sparse secret at the input
//! modulus, the modulus raised to the bootstrap width with the CoeffsToSlots
//! guard bits fused into the shift, a key switch back to the dense secret —
//! and then the raised metadata: the scale is the input modulus plus the
//! guard bits. This is the S2C-first raise (`lift = None`), not the C2S-first
//! one `ckks_bootstrap_mod_up` derives from the EvalMod plan.
//!
//! A submission with its own algorithm replaces the body of `run`. It gets
//! its state from `init` and the input, and must leave the same bytes in the
//! output as this reference does.

use poulpy_ckks::api::CKKSCopyOps;
use poulpy_ckks::layouts::BootstrappingKeys;
use poulpy_ckks::oep::CKKSEncapsulatedModUpImpl;
use poulpy_ckks::{CKKSInfos, CKKSMeta, SetCKKSInfos};
use poulpy_core::layouts::prepared::GGLWEPreparedToBackendRef;
use poulpy_core::layouts::LWEInfos;
use poulpy_hal::api::ScratchOwnedBorrow;

use crate::envelope::backend::BE;
use crate::envelope::{Input, Output};
use crate::init::State;

pub fn run<'a>(state: &'a mut State<'_>, input: &Input) -> &'a Output {
    let context = state.context;
    let State { source, output, scratch, .. } = state;
    let mut scratch = scratch.borrow();

    let guard = context.context.c2s_guard_bits();
    let log_modulus_in = input.ct.k().as_usize();
    let (d2s, s2d) = context
        .keys
        .encapsulation_keys()
        .expect("the preset encapsulates the raise in a sparse secret");

    // The buffers are reused: the source takes the input again, the output
    // goes back to the full width, before every run.
    source.set_k(input.ct.k());
    context.module.ckks_copy(source, &input.ct, &mut scratch).expect("copy the input");
    output.set_k(context.preset.bootstrap_k().into());
    <BE as CKKSEncapsulatedModUpImpl<BE>>::ckks_encapsulated_mod_up(
        &context.module,
        output,
        source,
        guard,
        &d2s.to_backend_ref(),
        &s2d.to_backend_ref(),
        &mut scratch,
    )
    .expect("ModUp");
    output.set_meta(CKKSMeta {
        log_sparsity: input.ct.log_sparsity(),
        log_delta: log_modulus_in + guard,
        slots: input.ct.slots(),
    });
    output
}

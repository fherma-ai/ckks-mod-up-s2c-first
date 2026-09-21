//! INIT — your setup. Over the point and the context, never a case. NOT
//! measured.
//!
//! The reference's: allocate a working copy of the input, the output buffer
//! and a working arena. A submission with a GPU would move the switching keys
//! to the card here; nothing computed here may depend on a case, and the
//! loop never shows it one. (`threads` in `config.jsonc` is read by the
//! envelope's `setup`: the pool is built once, before keygen.)

use poulpy_ckks::layouts::CKKSModuleAlloc;
use poulpy_hal::api::ScratchOwnedAlloc;
use poulpy_hal::layouts::ScratchOwned;

use crate::envelope::backend::BE;
use crate::envelope::{Context, Ct, Output};
use crate::fherma::Point;

/// Whatever `init` prepares and `run` needs.
pub struct State<'a> {
    pub context: &'a Context,
    /// The raise reads its source through a mutable borrow: the switch to the
    /// sparse secret happens in place. A copy of the input goes here first.
    pub source: Ct,
    /// Preallocated output; `run` writes into it. At the bootstrap layout: the
    /// raise leaves the output at the full bootstrap width.
    pub output: Output,
    pub scratch: ScratchOwned<BE>,
}

pub fn init<'a>(point: &Point, context: &'a Context, config: &str) -> State<'a> {
    let _ = (point, config);
    State {
        context,
        source: context
            .module
            .ckks_ciphertext_alloc_from_glwe_infos(&context.preset.input_layout()),
        output: context
            .module
            .ckks_ciphertext_alloc_from_glwe_infos(&context.preset.bootstrap_layout()),
        scratch: ScratchOwned::<BE>::alloc(context.scratch_bytes),
    }
}

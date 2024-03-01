//! [`LLVM` `PcGuard`](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards) runtime for `LibAFL`.

#[rustversion::nightly]
use core::simd::SimdUint;
#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ctx"))]
use core::{fmt::Debug, marker::PhantomData, ops::ShlAssign};

#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ctx"))]
use libafl::{
    bolts::tuples::Named, executors::ExitKind, inputs::UsesInput, observers::Observer, Error,
};
#[cfg(any(feature = "sancov_ngram4", feature = "sancov_ctx"))]
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "pointer_maps")]
use crate::coverage::{EDGES_MAP_PTR, EDGES_MAP_PTR_NUM};
use crate::{
    coverage::{EDGES_MAP, MAX_EDGES_NUM},
    EDGES_MAP_SIZE,
};
#[cfg(all(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts"))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!(
    "the libafl_targets `sancov_pcguard_edges` and `sancov_pcguard_hitcounts` features are mutually exclusive."
);

#[cfg(feature = "sancov_ngram4")]
#[rustversion::nightly]
type Ngram4 = core::simd::u32x4;

/// The array holding the previous locs. This is required for NGRAM-4 instrumentation
#[cfg(feature = "sancov_ngram4")]
#[rustversion::nightly]
pub static mut PREV_ARRAY: Ngram4 = Ngram4::from_array([0, 0, 0, 0]);

#[cfg(feature = "sancov_ngram4")]
#[rustversion::nightly]
pub static SHR: Ngram4 = Ngram4::from_array([1, 1, 1, 1]);
/// For resetting Ctx
#[derive(Debug, Serialize, Deserialize)]
pub struct CtxObserver<S> {
    phantom: PhantomData<S>,
}

impl<S> Named for CtxObserver<S> {
    fn name(&self) -> &str {
        "ctx"
    }
}

/// For resetting Ngram
#[derive(Debug, Serialize, Deserialize)]
pub struct NgramObserver<S> {
    phantom: PhantomData<S>,
}
impl<S> Named for NgramObserver<S> {
    fn name(&self) -> &str {
        "ngram"
    }
}

impl<S> NgramObserver<S> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<S> CtxObserver<S> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<S> Observer<S> for CtxObserver<S>
where
    S: UsesInput + Debug,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        unsafe {
            __afl_prev_ctx = 0;
        }
        Ok(())
    }

    #[inline]
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> Observer<S> for NgramObserver<S>
where
    S: UsesInput + Debug,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        unsafe {
            PREV_ARRAY = Ngram4::from_array([0, 0, 0, 0]);
        }
        Ok(())
    }

    #[inline]
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[rustversion::nightly]
#[cfg(feature = "sancov_ngram4")]
unsafe fn update_ngram(mut pos: usize) -> usize {
    PREV_ARRAY = PREV_ARRAY.rotate_lanes_right::<1>();
    PREV_ARRAY.shl_assign(SHR);
    PREV_ARRAY.as_mut_array()[0] = pos as u32;
    let mut reduced = PREV_ARRAY.reduce_xor() as usize;
    reduced %= EDGES_MAP_SIZE;
    reduced
}

#[rustversion::not(nightly)]
#[cfg(feature = "sancov_ngram4")]
unsafe fn update_ngram(pos: usize) -> usize {
    pos
}

extern "C" {
    /// The ctx variable
    pub static mut __afl_prev_ctx: u32;
}

/// Callback for sancov `pc_guard` - usually called by `llvm` on each block or edge.
///
/// # Safety
/// Dereferences `guard`, reads the position from there, then dereferences the [`EDGES_MAP`] at that position.
/// Should usually not be called directly.
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    let mut pos = *guard as usize;
    #[cfg(feature = "sancov_ngram4")]
    {
        pos = update_ngram(pos);
    }

    #[cfg(feature = "sancov_ctx")]
    {
        pos ^= __afl_prev_ctx as usize;
        pos = pos % EDGES_MAP_SIZE;
        // println!("Wrinting to {} {}", pos, EDGES_MAP_SIZE);
    }

    #[cfg(feature = "pointer_maps")]
    {
        #[cfg(feature = "sancov_pcguard_edges")]
        {
            (EDGES_MAP_PTR as *mut u8).add(pos).write(1);
        }
        #[cfg(feature = "sancov_pcguard_hitcounts")]
        {
            let addr = (EDGES_MAP_PTR as *mut u8).add(pos);
            let val = addr.read().wrapping_add(1);
            addr.write(val);
        }
    }
    #[cfg(not(feature = "pointer_maps"))]
    {
        #[cfg(feature = "sancov_pcguard_edges")]
        {
            *EDGES_MAP.get_unchecked_mut(pos) = 1;
        }
        #[cfg(feature = "sancov_pcguard_hitcounts")]
        {
            let val = (*EDGES_MAP.get_unchecked(pos)).wrapping_add(1);
            *EDGES_MAP.get_unchecked_mut(pos) = val;
        }
    }
}

/// Initialize the sancov `pc_guard` - usually called by `llvm`.
///
/// # Safety
/// Dereferences at `start` and writes to it.
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {
    #[cfg(feature = "pointer_maps")]
    if EDGES_MAP_PTR.is_null() {
        EDGES_MAP_PTR = EDGES_MAP.as_mut_ptr();
        EDGES_MAP_PTR_NUM = EDGES_MAP.len();
    }

    if start == stop || *start != 0 {
        return;
    }

    while start < stop {
        *start = MAX_EDGES_NUM as u32;
        start = start.offset(1);

        #[cfg(feature = "pointer_maps")]
        {
            MAX_EDGES_NUM = MAX_EDGES_NUM.wrapping_add(1) % EDGES_MAP_PTR_NUM;
        }
        #[cfg(not(feature = "pointer_maps"))]
        {
            MAX_EDGES_NUM = MAX_EDGES_NUM.wrapping_add(1);
            assert!((MAX_EDGES_NUM <= EDGES_MAP.len()), "The number of edges reported by SanitizerCoverage exceed the size of the edges map ({}). Use the LIBAFL_EDGES_MAP_SIZE env to increase it at compile time.", EDGES_MAP.len());
        }
    }
}

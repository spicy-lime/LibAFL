use core::{fmt::{Debug, self}, ops::Range};
use std::{borrow::Cow, cell::UnsafeCell, hash::BuildHasher};

use hashbrown::{HashMap, HashSet};
use libafl::{
    executors::ExitKind, inputs::UsesInput, observers::ObserversTuple, prelude::Feedback,
    state::State, HasMetadata,
};
use libafl_bolts::{
    impl_serdeany,
    tuples::{MatchFirstType, SplitBorrowExtractFirstType},
    Named,
};
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr};
use serde::Deserialize;

use crate::Qemu;

#[cfg(emulation_mode = "usermode")]
pub mod usermode;
#[cfg(emulation_mode = "usermode")]
pub use usermode::*;

#[cfg(emulation_mode = "systemmode")]
pub mod systemmode;
#[cfg(emulation_mode = "systemmode")]
pub use systemmode::*;

pub mod edges;
pub use edges::EdgeCoverageModule;

#[cfg(not(cpu_target = "hexagon"))]
pub mod calls;
#[cfg(not(cpu_target = "hexagon"))]
pub use calls::CallTracerModule;

#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub mod cmplog;
#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub use cmplog::CmpLogModule;
use serde::Serialize;

use crate::emu::EmulatorModules;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Predicate {
    Edges(GuestAddr, GuestAddr),
    Max(GuestAddr, u64),
}

impl fmt::Display for Predicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Predicate::Edges(addr1, addr2) => write!(f, "Edges({:#x}, {:#x})", addr1, addr2),
            Predicate::Max(addr, value) => write!(f, "Max({:#x}, {:#x})", addr, value),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Predicates {
    predicates: HashSet<Predicate>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PredicatesMap {
    map: HashMap<Predicate, (usize, usize)>,
}

impl PredicatesMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn sort_and_show(&self) {
        let mut entries: Vec<_> = self.map.iter().collect();
    
        // Sort entries based on the ratio (first usize) / (second usize)
        entries.sort_by(|a, b| {
            let ratio_a = a.1.0 as f64 / a.1.1 as f64;
            let ratio_b = b.1.0 as f64 / b.1.1 as f64;
            ratio_b.partial_cmp(&ratio_a).unwrap()
        });
    
        // Take the top 10 entries (or fewer if there are less than 10)
        let top_10 = entries.iter().take(10);
    
        println!("Top 10 entries with highest ratio:");
        for (i, (key, (first, second))) in top_10.enumerate() {
            let ratio = *first as f64 / *second as f64;
            println!("{}. {}: ({}, {}) - Ratio: {:.2}", i + 1, key, first, second, ratio);
        }
    }
}

impl_serdeany!(PredicatesMap);
impl_serdeany!(Predicates);

impl Predicates {
    pub fn new() -> Self {
        Self {
            predicates: HashSet::new(),
        }
    }

    pub fn add_edges(&mut self, src: GuestAddr, dest: GuestAddr) {
        self.predicates.insert(Predicate::Edges(src, dest));
    }

    pub fn clear(&mut self) {
        self.predicates.clear();
    }

    pub fn predicates(&self) -> &HashSet<Predicate> {
        &self.predicates
    }
}

pub struct PredicateFeedback {
    was_crash: bool,
}

impl Named for PredicateFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("predicates")
    }
}

impl PredicateFeedback {
    pub fn new() -> Self {
        Self { was_crash: false }
    }
}

impl<S> Feedback<S> for PredicateFeedback
where
    S: State + HasMetadata,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, libafl::Error>
    where
        EM: libafl::prelude::EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        match exit_kind {
            ExitKind::Ok => {
                self.was_crash = false;
                Ok(true)
            }
            ExitKind::Crash => {
                self.was_crash = true;
                Ok(true)
            }
            _ => {
                self.was_crash = false;
                Ok(false)
            }
        }
    }

    fn append_metadata<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut libafl::prelude::Testcase<<S>::Input>,
    ) -> Result<(), libafl::Error>
    where
        OT: ObserversTuple<S>,
        EM: libafl::prelude::EventFirer<State = S>,
    {
        let mut predicates = vec![];
        if let Ok(meta) = state.metadata::<Predicates>() {
            for predicate in &meta.predicates {
                predicates.push(predicate.clone());
            }
        }

        let map = state.metadata_or_insert_with(PredicatesMap::new);
        for predicate in predicates {
            if self.was_crash {
                map.map.entry(predicate)
                .and_modify(|e| {
                    e.0 += 1;
                    e.1 += 1
                })
                .or_insert((1, 1));
            }
            else{
                map.map.entry(predicate)
                .and_modify(|e| e.1 += 1)
                .or_insert((0, 1));
            }
        }

        map.sort_and_show();
        Ok(())
    }
}

/// A module for `libafl_qemu`.
// TODO remove 'static when specialization will be stable
pub trait EmulatorModule<S>: 'static + Debug
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    /// Initialize the module, mostly used to install some hooks early.
    fn init_module<ET>(&self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn first_exec<ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn pre_exec<ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>, _input: &S::Input)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn post_exec<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
    }
}

pub trait EmulatorModuleTuple<S>:
    MatchFirstType + for<'a> SplitBorrowExtractFirstType<'a> + Unpin
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool;

    fn init_modules_all<ET>(&self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>;

    fn first_exec_all<ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>;

    fn pre_exec_all<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>;

    fn post_exec_all<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>;
}

impl<S> EmulatorModuleTuple<S> for ()
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn init_modules_all<ET>(&self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn first_exec_all<ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn pre_exec_all<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
    }
}

impl<Head, Tail, S> EmulatorModuleTuple<S> for (Head, Tail)
where
    Head: EmulatorModule<S> + Unpin,
    Tail: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = Head::HOOKS_DO_SIDE_EFFECTS || Tail::HOOKS_DO_SIDE_EFFECTS;

    fn init_modules_all<ET>(&self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.init_module(emulator_modules);
        self.1.init_modules_all(emulator_modules);
    }

    fn first_exec_all<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.first_exec(emulator_modules);
        self.1.first_exec_all(emulator_modules);
    }

    fn pre_exec_all<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>, input: &S::Input)
    where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.pre_exec(emulator_modules, input);
        self.1.pre_exec_all(emulator_modules, input);
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
        self.0
            .post_exec(emulator_modules, input, observers, exit_kind);
        self.1
            .post_exec_all(emulator_modules, input, observers, exit_kind);
    }
}

impl HasInstrumentationFilter<()> for () {
    fn filter(&self) -> &() {
        self
    }

    fn filter_mut(&mut self) -> &mut () {
        self
    }
}

impl<Head, F> HasInstrumentationFilter<F> for (Head, ())
where
    Head: HasInstrumentationFilter<F>,
    F: IsFilter,
{
    fn filter(&self) -> &F {
        self.0.filter()
    }

    fn filter_mut(&mut self) -> &mut F {
        self.0.filter_mut()
    }
}

#[derive(Debug, Clone)]
pub enum QemuFilterList<T: IsFilter + Debug + Clone> {
    AllowList(T),
    DenyList(T),
    None,
}

impl<T> IsFilter for QemuFilterList<T>
where
    T: IsFilter + Clone,
{
    type FilterParameter = T::FilterParameter;

    fn allowed(&self, filter_parameter: Self::FilterParameter) -> bool {
        match self {
            QemuFilterList::AllowList(allow_list) => allow_list.allowed(filter_parameter),
            QemuFilterList::DenyList(deny_list) => !deny_list.allowed(filter_parameter),
            QemuFilterList::None => true,
        }
    }
}

pub type QemuInstrumentationPagingFilter = QemuFilterList<HashSet<GuestPhysAddr>>;

impl<H> IsFilter for HashSet<GuestPhysAddr, H>
where
    H: BuildHasher,
{
    type FilterParameter = Option<GuestPhysAddr>;

    fn allowed(&self, paging_id: Self::FilterParameter) -> bool {
        paging_id.is_some_and(|pid| self.contains(&pid))
    }
}

pub type QemuInstrumentationAddressRangeFilter = QemuFilterList<Vec<Range<GuestAddr>>>;

impl IsFilter for Vec<Range<GuestAddr>> {
    type FilterParameter = GuestAddr;

    fn allowed(&self, addr: Self::FilterParameter) -> bool {
        for rng in self {
            if rng.contains(&addr) {
                return true;
            }
        }
        false
    }
}

pub trait HasInstrumentationFilter<F>
where
    F: IsFilter,
{
    fn filter(&self) -> &F;

    fn filter_mut(&mut self) -> &mut F;

    fn update_filter(&mut self, filter: F, emu: &Qemu) {
        *self.filter_mut() = filter;
        emu.flush_jit();
    }
}

static mut EMPTY_ADDRESS_FILTER: UnsafeCell<QemuInstrumentationAddressRangeFilter> =
    UnsafeCell::new(QemuFilterList::None);
static mut EMPTY_PAGING_FILTER: UnsafeCell<QemuInstrumentationPagingFilter> =
    UnsafeCell::new(QemuFilterList::None);

impl HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter> for () {
    fn filter(&self) -> &QemuInstrumentationAddressRangeFilter {
        &QemuFilterList::None
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationAddressRangeFilter {
        unsafe { EMPTY_ADDRESS_FILTER.get_mut() }
    }
}

impl HasInstrumentationFilter<QemuInstrumentationPagingFilter> for () {
    fn filter(&self) -> &QemuInstrumentationPagingFilter {
        &QemuFilterList::None
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationPagingFilter {
        unsafe { EMPTY_PAGING_FILTER.get_mut() }
    }
}

pub trait IsFilter: Debug {
    type FilterParameter;

    fn allowed(&self, filter_parameter: Self::FilterParameter) -> bool;
}

impl IsFilter for () {
    type FilterParameter = ();

    fn allowed(&self, _filter_parameter: Self::FilterParameter) -> bool {
        true
    }
}

pub trait IsAddressFilter: IsFilter<FilterParameter = GuestAddr> {}

impl IsAddressFilter for QemuInstrumentationAddressRangeFilter {}

#[must_use]
pub fn hash_me(mut x: u64) -> u64 {
    x = (x.overflowing_shr(16).0 ^ x).overflowing_mul(0x45d9f3b).0;
    x = (x.overflowing_shr(16).0 ^ x).overflowing_mul(0x45d9f3b).0;
    x = (x.overflowing_shr(16).0 ^ x) ^ x;
    x
}

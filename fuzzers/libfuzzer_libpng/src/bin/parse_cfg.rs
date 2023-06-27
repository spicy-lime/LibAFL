use libafl_cc::cfg::{ControlFlowGraph, HasWeight};

#[derive(Debug)]
struct TestMetaData {}


    impl HasWeight<TestMetaData> for TestMetaData {
        fn compute(_metadata: Option<&TestMetaData>) -> u32 {
            1
        }
    }

fn main() {
    let cfg_str = include_str!("../../test1.c.cfg");
    let cfg: ControlFlowGraph<TestMetaData> = ControlFlowGraph::from_content(cfg_str);
    println!("{cfg:?}");
}

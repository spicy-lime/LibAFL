use std::env;

use libafl_cc::{ClangWrapper, CompilerWrapper, LLVMPasses};

pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

        let is_cpp = match wrapper_name[wrapper_name.len()-2..].to_lowercase().as_str() {
            "cc" => false,
            "++" | "pp" | "xx" => true,
            _ => panic!("Could not figure out if c or c++ wrapper was called. Expected {dir:?} to end with c or cxx"),
        };

        dir.pop();

        let input_file = if is_cpp {
            args.iter().find(|x| x.ends_with(".cc"))
        } else {
            args.iter().find(|x| x.ends_with(".c"))
        }.map(|x| x.as_str()).unwrap_or("unknown");

        let input_file = input_file.split("/").last().unwrap();
        println!("input_file: {input_file}");

        let mut cc = ClangWrapper::new();
        if let Some(code) = cc
            .cpp(is_cpp)
            // silence the compiler wrapper output, needed for some configure scripts.
            .silence(true)
            .parse_args(&args)
            .expect("Failed to parse the command line")
            .link_staticlib(&dir, "libfuzzer_libpng")
            .add_pass(LLVMPasses::AFLCoverage)
            .add_passes_arg("-dump_afl_cfg")
            .add_passes_arg(format!("-dump_afl_cfg_path=./{input_file}.cfg"))
            .run()
            .expect("Failed to run the wrapped compiler")
        {
            std::process::exit(code);
        }
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}

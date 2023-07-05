cargo build --release && ./target/release/libafl_cc -o fuzzer fuzzer.c && LIBAFL_DEBUG_OUTPUT=1 RUST_BACKTRACE=full ./fuzzer.asan_coverage --cores=0-1 --input ./inputs

#![no_main]
use libfuzzer_sys::fuzz_target;
use zeus_attack::wordlist::parse_wordlist_line;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_wordlist_line(s);
    }
});

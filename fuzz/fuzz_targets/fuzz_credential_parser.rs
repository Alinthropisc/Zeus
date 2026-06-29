#![no_main]
use libfuzzer_sys::fuzz_target;
use zeus_attack::wordlist::Wordlist;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let entries: Vec<String> = s.lines().map(|l| l.to_string()).collect();
        let wl = Wordlist::from_vec(entries);
        let _ = wl.len();
        let _ = wl.passwords().count();
    }
});

#![no_main]
use libfuzzer_sys::fuzz_target;
use zeus_output::cvss::CvssV3Builder;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 8 {
        let _ = CvssV3Builder::from_bytes(data);
    }
});

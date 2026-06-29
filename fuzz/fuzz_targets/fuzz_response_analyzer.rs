#![no_main]
use libfuzzer_sys::fuzz_target;
use zeus_core::response_analyzer::ResponseAnalyzer;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let analyzer = ResponseAnalyzer::default();
        let _ = analyzer.analyze(s);
    }
});

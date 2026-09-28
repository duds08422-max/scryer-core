//! report — konsolowy raport pipeline'u (ładny, stabilny output).

use crate::score::PipelineReport;

impl PipelineReport {
    /// Jednolinijkowe podsumowanie (do logów).
    pub fn line(&self) -> String {
        format!(
            "loaded={} kept={} invalid/dup={} HOT={} WARM={} COLD={}",
            self.loaded, self.deduped, self.dropped_invalid, self.hot, self.warm, self.cold
        )
    }
}

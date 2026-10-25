//! Optional aggregate diagnostics for the public guest download path.

use std::{
    io::Write,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) struct DownloadStep {
    elapsed: Option<Duration>,
    started: Option<Instant>,
}

impl DownloadStep {
    pub(super) fn start(&mut self) {
        self.started = Some(Instant::now());
    }

    pub(super) fn finish(&mut self) {
        if let Some(started) = self.started.take() {
            *self.elapsed.get_or_insert(Duration::ZERO) += started.elapsed();
        }
    }

    fn seconds(&self) -> Option<f64> {
        match (self.elapsed, self.started) {
            (None, None) => None,
            (elapsed, started) => Some(
                (elapsed.unwrap_or_default() + started.map(|s| s.elapsed()).unwrap_or_default())
                    .as_secs_f64(),
            ),
        }
    }
}

pub(super) struct DownloadTiming {
    pub(super) started: Instant,
    pub(super) request_setup: DownloadStep,
    pub(super) stream_try_next: DownloadStep,
    pub(super) compressed_write: DownloadStep,
    // Queueing can overlap decode/output. It measures backpressure, not the
    // worker's CPU or file-write time. Finish includes any remaining queued work.
    pub(super) decoder_enqueue: DownloadStep,
    pub(super) compressed_flush: DownloadStep,
    pub(super) compressed_sync: DownloadStep,
    pub(super) decoder_finish: DownloadStep,
    pub(super) chunks: u64,
    pub(super) bytes: u64,
    pub(super) first_chunk_at_s: Option<f64>,
    pub(super) last_chunk_at_s: Option<f64>,
    pub(super) eof_at_s: Option<f64>,
    pub(super) cache_hit: bool,
    pub(super) archive_verified: bool,
    pub(super) decoder_status: &'static str,
}

impl DownloadTiming {
    pub(super) fn from_env() -> Option<Self> {
        if std::env::var_os("SAFEYOLO_GUEST_DOWNLOAD_TIMING").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return None;
        }
        let mut timing = Self {
            started: Instant::now(),
            request_setup: DownloadStep::default(),
            stream_try_next: DownloadStep::default(),
            compressed_write: DownloadStep::default(),
            decoder_enqueue: DownloadStep::default(),
            compressed_flush: DownloadStep::default(),
            compressed_sync: DownloadStep::default(),
            decoder_finish: DownloadStep::default(),
            chunks: 0,
            bytes: 0,
            first_chunk_at_s: None,
            last_chunk_at_s: None,
            eof_at_s: None,
            cache_hit: false,
            archive_verified: false,
            decoder_status: "not_requested",
        };
        timing.request_setup.start();
        Some(timing)
    }
}

impl Drop for DownloadTiming {
    fn drop(&mut self) {
        // Include an in-flight await on cancellation. Diagnostic output must
        // never turn a successful acquisition into an installation failure.
        let summary = serde_json::json!({
            "elapsed_s": self.started.elapsed().as_secs_f64(),
            "request_setup_s": self.request_setup.seconds(),
            "chunks": self.chunks,
            "bytes": self.bytes,
            "first_chunk_at_s": self.first_chunk_at_s,
            "last_chunk_at_s": self.last_chunk_at_s,
            "eof_at_s": self.eof_at_s,
            "stream_try_next_s": self.stream_try_next.seconds(),
            "compressed_write_s": self.compressed_write.seconds(),
            "decoder_enqueue_s": self.decoder_enqueue.seconds(),
            "compressed_flush_s": self.compressed_flush.seconds(),
            "compressed_sync_s": self.compressed_sync.seconds(),
            "decoder_finish_s": self.decoder_finish.seconds(),
            "cache_hit": self.cache_hit,
            "archive_verified": self.archive_verified,
            "decoder_status": self.decoder_status,
        });
        let _ = writeln!(
            std::io::stderr().lock(),
            "SafeYolo: guest download timing {summary}"
        );
    }
}

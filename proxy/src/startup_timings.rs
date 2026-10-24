//! Monotonic wall and process CPU checkpoints for native startup diagnosis.

use std::time::{Duration, Instant};

pub struct StartupTimings {
    component: &'static str,
    began: Instant,
    previous: Instant,
    cpu: Option<Duration>,
}

impl StartupTimings {
    pub fn new(component: &'static str) -> Self {
        let began = Instant::now();
        Self {
            component,
            began,
            previous: began,
            cpu: process_cpu(),
        }
    }

    pub fn record(&mut self, stage: &'static str) {
        let now = Instant::now();
        let cpu = process_cpu();
        eprintln!(
            "startup {}",
            serde_json::json!({
                "component": self.component,
                "stage": stage,
                "source": env!("SAFEYOLO_BUILD_REVISION"),
                "profile": env!("SAFEYOLO_BUILD_PROFILE"),
                "pid": std::process::id(),
                "elapsed_seconds": now.duration_since(self.began).as_secs_f64(),
                "stage_seconds": now.duration_since(self.previous).as_secs_f64(),
                "stage_cpu_seconds": cpu.zip(self.cpu)
                    .and_then(|(current, previous)| current.checked_sub(previous))
                    .map(|duration| duration.as_secs_f64()),
            })
        );
        self.previous = now;
        self.cpu = cpu;
    }
}

fn process_cpu() -> Option<Duration> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time) } != 0 {
        return None;
    }
    Some(Duration::new(
        time.tv_sec.try_into().ok()?,
        time.tv_nsec.try_into().ok()?,
    ))
}

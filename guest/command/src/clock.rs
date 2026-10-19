//! Guest-local wall clock repair from the VZ real-time clock (RTC).

use crate::{Error, read_json, write_json};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read},
    path::Path,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const SOURCE: &str = "/sys/class/rtc/rtc0/since_epoch";
const STATUS: &str = "/run/safeyolo/clock.json";
const INTERVAL: Duration = Duration::from_secs(5);
// The kernel reports whole RTC seconds. Observe more than one tick before
// accepting the source, including on the first check after a restore.
const TICK: Duration = Duration::from_millis(1100);

fn read_rtc(path: &Path) -> Result<i64, Error> {
    let mut text = String::new();
    fs::File::open(path)?.take(64).read_to_string(&mut text)?;
    Ok(text.trim().parse()?)
}

fn check_tick(before: i64, after: i64) -> Result<(), Error> {
    if after <= before {
        return Err("RTC did not advance; inspect rtc0 and the VM clock source".into());
    }
    Ok(())
}

fn wall_time() -> f64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(time) => time.as_secs_f64(),
        Err(error) => -error.duration().as_secs_f64(),
    }
}

fn set_wall_time(seconds: i64) -> Result<(), Error> {
    let time = libc::timespec {
        tv_sec: seconds,
        tv_nsec: 0,
    };
    // This command runs as guest root on VZ. It is never started on gVisor,
    // where the sandbox must not acquire a host clock capability.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &time) } != 0 {
        return Err(format!(
            "cannot set the guest clock: {}; check guest-local CAP_SYS_TIME",
            io::Error::last_os_error()
        )
        .into());
    }
    Ok(())
}

fn adjust_guest_clock(
    source: i64,
    offset: f64,
    set_time: impl FnOnce(i64) -> Result<(), Error>,
) -> Result<bool, Error> {
    // A difference of up to one second can be RTC quantisation. Avoid
    // stepping a healthy clock on every check.
    if offset.abs() <= 1.0 {
        return Ok(false);
    }
    set_time(source)?;
    Ok(true)
}

fn correct(report: &mut Value) -> Result<(), Error> {
    let before = read_rtc(Path::new(SOURCE))?;
    thread::sleep(TICK);
    let source = read_rtc(Path::new(SOURCE))?;
    check_tick(before, source)?;
    let offset = source as f64 - wall_time();
    report["offset_seconds"] = json!(offset);
    let adjusted = adjust_guest_clock(source, offset, set_wall_time)?;
    let remaining = read_rtc(Path::new(SOURCE))? as f64 - wall_time();
    report["remaining_offset_seconds"] = json!(remaining);
    if remaining.abs() > 2.0 {
        return Err(format!(
            "guest clock is still {remaining:.3}s from rtc0 after adjustment; inspect VM clock diagnostics"
        )
        .into());
    }
    if adjusted {
        report["last_correction_at"] = json!(wall_time());
    }
    report["state"] = json!(if adjusted { "corrected" } else { "aligned" });
    report["checked_at"] = json!(wall_time());
    Ok(())
}

pub(super) fn run(watch: bool) -> Result<i32, Error> {
    if fs::read_to_string("/proc/sys/kernel/osrelease")?
        .trim()
        .ends_with("-gvisor")
    {
        println!("[guest-clock] source=host backend=gvisor; no guest clock adjustment");
        return Ok(0);
    }
    let status = Path::new(STATUS);
    let mut last_correction = match read_json(status, 4096) {
        Ok(value) => value["last_correction_at"].clone(),
        // A new guest has no previous correction.
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
        {
            Value::Null
        }
        Err(error) => {
            eprintln!("[guest-clock] previous correction is unknown: {error}");
            Value::Null
        }
    };
    let mut previous_failure = None;
    loop {
        let mut report = json!({"source":SOURCE,"last_correction_at":last_correction});
        let result = correct(&mut report);
        if let Err(error) = &result {
            report["state"] = json!("failed");
            report["error"] = json!(error.to_string());
        }
        last_correction = report["last_correction_at"].clone();
        let diagnostic = write_json(status, &report);
        if let Err(error) = &diagnostic {
            report["diagnostic_error"] = json!(format!("cannot write {STATUS}: {error}"));
        }
        let failure = result
            .as_ref()
            .err()
            .or(diagnostic.as_ref().err())
            .map(ToString::to_string);
        if !watch || report["state"] == "corrected" || failure != previous_failure {
            eprintln!("[guest-clock] {report}");
        }
        previous_failure = failure;
        if !watch {
            return Ok(i32::from(result.is_err() || diagnostic.is_err()));
        }
        thread::sleep(INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correction_steps_in_both_directions_but_keeps_rtc_quantisation() {
        for offset in [-600.0, -1.01, 1.01, 600.0] {
            let mut set = None;
            assert!(
                adjust_guest_clock(1792430229, offset, |time| {
                    set = Some(time);
                    Ok(())
                })
                .unwrap()
            );
            assert_eq!(set, Some(1792430229));
        }
        for offset in [-1.0, -0.5, 0.0, 0.5, 1.0] {
            assert!(
                !adjust_guest_clock(1792430229, offset, |_| panic!("healthy clock was stepped"))
                    .unwrap()
            );
        }
    }

    #[test]
    fn denied_adjustment_is_an_error_and_the_next_attempt_can_recover() {
        let error = adjust_guest_clock(1792430229, 600.0, |_| {
            Err(io::Error::from_raw_os_error(libc::EPERM).into())
        })
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::EPERM)
        );
        assert!(adjust_guest_clock(1792430229, 600.0, |_| Ok(())).unwrap());
    }

    #[test]
    fn frozen_or_reversed_rtc_is_not_a_success() {
        assert!(check_tick(100, 101).is_ok());
        assert!(check_tick(100, 105).is_ok());
        for after in [100, 99, 0] {
            assert!(
                check_tick(100, after)
                    .unwrap_err()
                    .to_string()
                    .contains("did not advance")
            );
        }
    }

    #[test]
    fn unavailable_or_invalid_rtc_is_not_a_time_sample() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("since_epoch");
        assert!(read_rtc(&source).is_err());
        for text in [
            "",
            "unavailable",
            "1792430229 garbage",
            "9999999999999999999999999999999999999999",
        ] {
            fs::write(&source, text).unwrap();
            assert!(read_rtc(&source).is_err());
        }
        fs::write(&source, "1792430229\n").unwrap();
        assert_eq!(read_rtc(&source).unwrap(), 1792430229);
    }
}

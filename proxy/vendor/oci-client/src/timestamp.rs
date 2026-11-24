//! UTC image timestamps, including extended years and explicit leap seconds.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::{Date, Month, OffsetDateTime, Time, UtcOffset};

/// An image timestamp normalized to UTC without discarding a leap second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageTimestamp {
    utc: OffsetDateTime,
    leap_second: bool,
}

fn take_digits<'a>(input: &mut &'a str, max: usize) -> Option<&'a str> {
    let length = input
        .bytes()
        .take(max)
        .take_while(u8::is_ascii_digit)
        .count();
    if length == 0 {
        return None;
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Some(value)
}

fn parse_number(input: &mut &str, max: usize) -> Option<u32> {
    *input = input.trim_start();
    take_digits(input, max)?.parse().ok()
}

fn consume_separator(input: &mut &str, character: char) -> Option<()> {
    *input = input.trim_start().strip_prefix(character)?;
    Some(())
}

impl ImageTimestamp {
    fn parse(mut input: &str) -> Option<Self> {
        input = input.trim_start();
        let (sign, year_digits) = if let Some(rest) = input.strip_prefix('-') {
            input = rest;
            (-1, usize::MAX)
        } else if let Some(rest) = input.strip_prefix('+') {
            input = rest;
            (1, usize::MAX)
        } else {
            (1, 4)
        };
        let year = i32::try_from(parse_number(&mut input, year_digits)?).ok()? * sign;
        consume_separator(&mut input, '-')?;
        let month = Month::try_from(parse_number(&mut input, 2)? as u8).ok()?;
        consume_separator(&mut input, '-')?;
        let day = parse_number(&mut input, 2)? as u8;
        let date = Date::from_calendar_date(year, month, day).ok()?;
        input = input.strip_prefix(['T', 't', ' '])?;
        let hour = parse_number(&mut input, 2)? as u8;
        consume_separator(&mut input, ':')?;
        let minute = parse_number(&mut input, 2)? as u8;
        consume_separator(&mut input, ':')?;
        let second = parse_number(&mut input, 2)? as u8;
        let nanos = if let Some(rest) = input.strip_prefix('.') {
            input = rest;
            let fraction = take_digits(&mut input, usize::MAX)?;
            fraction
                .bytes()
                .take(9)
                .fold(0u32, |n, b| n * 10 + u32::from(b - b'0'))
                * 10u32.pow(9 - fraction.len().min(9) as u32)
        } else {
            0
        };
        input = input.trim_start();
        let offset = if input
            .get(..3)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("UTC"))
        {
            input = &input[3..];
            UtcOffset::UTC
        } else if let Some(rest) = input.strip_prefix(['Z', 'z']) {
            input = rest;
            UtcOffset::UTC
        } else {
            let sign = match input.chars().next()? {
                '+' => {
                    input = &input[1..];
                    1
                }
                '-' => {
                    input = &input[1..];
                    -1
                }
                '−' => {
                    input = &input['−'.len_utf8()..];
                    -1
                }
                _ => return None,
            };
            let hour = take_digits(&mut input, 2)?;
            if hour.len() != 2 {
                return None;
            }
            let hour: i8 = hour.parse().ok()?;
            input = input.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
            let minute = take_digits(&mut input, 2)?;
            if minute.len() != 2 {
                return None;
            }
            let minute: i8 = minute.parse().ok()?;
            if hour > 23 || minute > 59 {
                return None;
            }
            UtcOffset::from_hms(sign * hour, sign * minute, 0).ok()?
        };
        if !input.trim_start().is_empty() {
            return None;
        }
        let leap_second = second == 60;
        let time =
            Time::from_hms_nano(hour, minute, if leap_second { 59 } else { second }, nanos).ok()?;
        let utc =
            OffsetDateTime::new_in_offset(date, time, offset).checked_to_offset(UtcOffset::UTC)?;
        Some(Self { utc, leap_second })
    }
}

impl FromStr for ImageTimestamp {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input).ok_or_else(|| format!("invalid image timestamp: {input:?}"))
    }
}

impl fmt::Display for ImageTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let year = self.utc.year();
        if (0..=9999).contains(&year) {
            write!(f, "{year:04}")?;
        } else if year < 0 {
            write!(f, "-{:04}", -year)?;
        } else {
            write!(f, "+{year}")?;
        }
        write!(
            f,
            "-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.utc.month() as u8,
            self.utc.day(),
            self.utc.hour(),
            self.utc.minute(),
            if self.leap_second {
                60
            } else {
                self.utc.second()
            }
        )?;
        let nanos = self.utc.nanosecond();
        if nanos != 0 {
            if nanos % 1_000_000 == 0 {
                write!(f, ".{:03}", nanos / 1_000_000)?;
            } else if nanos % 1_000 == 0 {
                write!(f, ".{:06}", nanos / 1_000)?;
            } else {
                write!(f, ".{nanos:09}")?;
            }
        }
        f.write_str("Z")
    }
}

impl Serialize for ImageTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ImageTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::ImageTimestamp;

    #[test]
    fn dates_normalize_without_losing_precision_or_leap_seconds() {
        for (input, expected) in [
            (
                "2024-02-29T23:59:59.123456789-05:30",
                "2024-03-01T05:29:59.123456789Z",
            ),
            ("2000-01-01T00:00:00+14:00", "1999-12-31T10:00:00Z"),
            (
                "2017-01-01T01:29:60.123456789123+01:30",
                "2016-12-31T23:59:60.123456789Z",
            ),
            ("-0001-01-01T00:00:00Z", "-0001-01-01T00:00:00Z"),
            ("+12345-01-01T00:00:00Z", "+12345-01-01T00:00:00Z"),
            ("2024-01-01T00:00:00.1Z", "2024-01-01T00:00:00.100Z"),
            (" 2015 - 1 - 1 1 : 2 : 3 UTC ", "2015-01-01T01:02:03Z"),
            ("2015-1-1t1:2:3+0200", "2014-12-31T23:02:03Z"),
            ("2015-1-1T1:2:3−02:00", "2015-01-01T03:02:03Z"),
        ] {
            let parsed: ImageTimestamp = input.parse().unwrap();
            assert_eq!(parsed.to_string(), expected);
            assert_eq!(expected.parse::<ImageTimestamp>().unwrap(), parsed);
        }
    }

    #[test]
    fn invalid_calendar_and_clock_components_are_refused() {
        for input in [
            "2023-02-29T00:00:00Z",
            "2024-13-01T00:00:00Z",
            "2024-01-01T24:00:00Z",
            "2024-01-01T00:00:61Z",
            "2024-01-01T00:00:00.Z",
            "2024-01-01T00:00:00+01:99",
            "2024-01-01T00:00:00+01:-30",
            "not-a-date",
            "2024-01-01T00:00:00+24:00",
            "2024-01-01T00:00:00Ztrailing",
            "2024-+1-01T00:00:00Z",
        ] {
            assert!(input.parse::<ImageTimestamp>().is_err(), "{input}");
        }
    }
}

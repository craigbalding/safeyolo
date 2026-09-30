//! Circuit numeric kinds, opaque temporal operands, and source scalar operations.

use std::{cmp::Ordering, fmt};

use indexmap::IndexMap;
use num_bigint::{BigInt, BigUint, Sign};
use serde::{Serialize, Serializer, ser::Error as _};
use serde_json::Value;

use super::{ErrorKind, Result, failure_kind};
use crate::policy::TimestampPaths;

/// A circuit field retains its Python numeric kind until an operation consumes
/// it. Non-numeric persisted/configured values are likewise left untouched.
pub enum CircuitValue {
    Bool(bool),
    Integer(BigInt),
    Float(f64),
    Other(Value),
    Temporal(TemporalOperand),
    Array(Vec<CircuitValue>),
    Object(IndexMap<String, CircuitValue>),
}

/// An operand containing genuine parser-owned temporal values or keys.
/// Its JSON-shaped storage is private and is never serialized as ordinary data.
#[derive(Clone)]
pub struct TemporalOperand {
    value: Value,
    timestamps: TimestampPaths,
}

impl PartialEq for TemporalOperand {
    fn eq(&self, other: &Self) -> bool {
        let mut pending = vec![(
            &self.value,
            &other.value,
            Vec::<String>::new(),
            Vec::<String>::new(),
        )];
        while let Some((left, right, left_path, right_path)) = pending.pop() {
            let lp: Vec<_> = left_path.iter().map(String::as_str).collect();
            let rp: Vec<_> = right_path.iter().map(String::as_str).collect();
            match (
                self.timestamps.value_at(&lp),
                other.timestamps.value_at(&rp),
            ) {
                (Some(left), Some(right)) if left == right => continue,
                (None, None) => {}
                _ => return false,
            }
            match (left, right) {
                (Value::Array(left), Value::Array(right)) if left.len() == right.len() => {
                    for (index, (left, right)) in left.iter().zip(right).enumerate() {
                        let mut lp = left_path.clone();
                        lp.push(index.to_string());
                        let mut rp = right_path.clone();
                        rp.push(index.to_string());
                        pending.push((left, right, lp, rp));
                    }
                }
                (Value::Object(left), Value::Object(right)) if left.len() == right.len() => {
                    for (key, left) in left {
                        let mut key_path = lp.clone();
                        key_path.push(key);
                        let matched = if let Some(temporal) = self.timestamps.key_at(&key_path) {
                            right.iter().find(|(key, _)| {
                                let mut key_path = rp.clone();
                                key_path.push(key);
                                other.timestamps.key_at(&key_path) == Some(temporal)
                            })
                        } else {
                            right.get(key).map(|value| (key, value)).filter(|(key, _)| {
                                let mut key_path = rp.clone();
                                key_path.push(key);
                                other.timestamps.key_at(&key_path).is_none()
                            })
                        };
                        let Some((right_key, right)) = matched else {
                            return false;
                        };
                        let mut lp = left_path.clone();
                        lp.push(key.clone());
                        let mut rp = right_path.clone();
                        rp.push(right_key.clone());
                        pending.push((left, right, lp, rp));
                    }
                }
                _ if left == right => {}
                _ => return false,
            }
        }
        true
    }
}

impl fmt::Debug for CircuitValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(value) => value.fmt(f),
            Self::Integer(value) => value.fmt(f),
            Self::Float(value) => value.fmt(f),
            Self::Other(_) | Self::Temporal(_) | Self::Array(_) | Self::Object(_) => {
                f.write_str("<non-numeric circuit field>")
            }
        }
    }
}

impl From<Value> for CircuitValue {
    fn from(value: Value) -> Self {
        Self::from_json_value(&value)
    }
}
impl From<f64> for CircuitValue {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}
impl From<BigInt> for CircuitValue {
    fn from(value: BigInt) -> Self {
        Self::Integer(value)
    }
}
macro_rules! integer_from {
    ($($ty:ty),*) => {$(
        impl From<$ty> for CircuitValue {
            fn from(value: $ty) -> Self { Self::Integer(BigInt::from(value)) }
        }
        impl PartialEq<$ty> for CircuitValue {
            fn eq(&self, other: &$ty) -> bool { self.equal(&Self::from(*other)) }
        }
    )*};
}
integer_from!(i32, i64, u64);
impl PartialEq<f64> for CircuitValue {
    fn eq(&self, other: &f64) -> bool {
        self.equal(&Self::Float(*other))
    }
}

impl Serialize for CircuitValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.json().map_err(S::Error::custom)?.serialize(serializer)
    }
}

impl CircuitValue {
    pub(crate) fn from_annotated(value: Value, timestamps: TimestampPaths) -> Self {
        if timestamps.has_under(&[]) {
            Self::Temporal(TemporalOperand { value, timestamps })
        } else {
            Self::from(value)
        }
    }

    pub(crate) fn annotated(&self) -> Option<(&Value, &TimestampPaths)> {
        match self {
            Self::Temporal(operand) => Some((&operand.value, &operand.timestamps)),
            _ => None,
        }
    }

    pub(crate) fn json(&self) -> Result<Value> {
        Ok(match self {
            Self::Bool(value) => Value::Bool(*value),
            Self::Integer(value) => Value::Number(value.to_string().parse().expect("integer JSON")),
            Self::Float(value) if !value.is_finite() => {
                return Err(failure_kind(
                    ErrorKind::Compatibility,
                    "nonfinite circuit value requires typed JSON output",
                ));
            }
            Self::Float(value) => Value::Number(serde_json::Number::from_f64(*value).unwrap()),
            Self::Other(value) => value.clone(),
            Self::Temporal(_) => return Err(type_error()),
            Self::Array(_) | Self::Object(_) => return super::json::to_value(self),
        })
    }

    pub(crate) fn integer(&self) -> Option<BigInt> {
        match self {
            Self::Bool(value) => Some(BigInt::from(u8::from(*value))),
            Self::Integer(value) => Some(value.clone()),
            _ => None,
        }
    }

    pub(super) fn float(&self) -> Result<f64> {
        match self {
            Self::Float(value) => Ok(*value),
            Self::Other(_) | Self::Temporal(_) | Self::Array(_) | Self::Object(_) => {
                Err(type_error())
            }
            value => {
                let value: f64 = value.integer().unwrap().to_string().parse().unwrap();
                if value.is_infinite() {
                    Err(failure_kind(
                        ErrorKind::Overflow,
                        "integer too large to convert to float",
                    ))
                } else {
                    Ok(value)
                }
            }
        }
    }

    pub(crate) fn truthy(&self) -> bool {
        match self {
            Self::Bool(value) => *value,
            Self::Integer(value) => value != &BigInt::from(0),
            Self::Float(value) => *value != 0.,
            Self::Other(value) => super::truthy(value),
            Self::Temporal(operand) => {
                operand.timestamps.value_at(&[]).is_some() || super::truthy(&operand.value)
            }
            Self::Array(values) => !values.is_empty(),
            Self::Object(values) => !values.is_empty(),
        }
    }

    pub(super) fn equal(&self, other: &Self) -> bool {
        self.compare(other)
            .is_ok_and(|value| value == Some(Ordering::Equal))
    }

    pub(crate) fn compare(&self, other: &Self) -> Result<Option<Ordering>> {
        Ok(match (self.integer(), other.integer()) {
            (Some(left), Some(right)) => Some(left.cmp(&right)),
            (Some(left), None) => match other {
                Self::Float(right) => int_float_cmp(&left, *right),
                _ => return Err(type_error()),
            },
            (None, Some(right)) => match self {
                Self::Float(left) => int_float_cmp(&right, *left).map(Ordering::reverse),
                _ => return Err(type_error()),
            },
            _ => self.float()?.partial_cmp(&other.float()?),
        })
    }
    pub(super) fn greater(&self, other: &Self) -> Result<bool> {
        Ok(self.compare(other)? == Some(Ordering::Greater))
    }
    pub(super) fn at_least(&self, other: &Self) -> Result<bool> {
        Ok(matches!(
            self.compare(other)?,
            Some(Ordering::Equal | Ordering::Greater)
        ))
    }
    pub(super) fn min_first(self, other: Self) -> Result<Self> {
        Ok(if other.compare(&self)? == Some(Ordering::Less) {
            other
        } else {
            self
        })
    }
    pub(super) fn max_first(self, other: Self) -> Result<Self> {
        Ok(if other.greater(&self)? { other } else { self })
    }
    pub(super) fn add(&self, other: &Self) -> Result<Self> {
        Ok(match (self.integer(), other.integer()) {
            (Some(left), Some(right)) => (left + right).into(),
            _ => Self::Float(self.float()? + other.float()?),
        })
    }
    pub(super) fn subtract(&self, other: &Self) -> Result<Self> {
        Ok(match (self.integer(), other.integer()) {
            (Some(left), Some(right)) => (left - right).into(),
            _ => Self::Float(self.float()? - other.float()?),
        })
    }
    pub(super) fn multiply(&self, other: &Self) -> Result<Self> {
        Ok(match (self.integer(), other.integer()) {
            (Some(left), Some(right)) => (left * right).into(),
            _ => Self::Float(self.float()? * other.float()?),
        })
    }
    pub(super) fn negative(&self) -> Result<Self> {
        Ok(match self.integer() {
            Some(value) => (-value).into(),
            None => Self::Float(-self.float()?),
        })
    }
    pub(crate) fn divide(&self, other: &Self) -> Result<Self> {
        if let (Some(left), Some(right)) = (self.integer(), other.integer()) {
            return integer_ratio(&left, &right).map(Self::Float);
        }
        let left = self.float()?;
        let right = other.float()?;
        if right == 0. {
            return Err(zero_division());
        }
        Ok(Self::Float(left / right))
    }
    pub(super) fn logarithm(&self) -> Result<f64> {
        if let Some(value) = self.integer() {
            if value <= BigInt::from(0) {
                return Err(value_error());
            }
            let converted: f64 = value.to_string().parse().unwrap();
            if converted.is_finite() {
                return Ok(converted.ln());
            }
            // Python math.log accepts integers beyond binary64's range. Scale
            // before conversion; the extracted fraction is rounded to even.
            let bits = value.bits();
            let denominator =
                BigInt::from(1) << usize::try_from(bits).expect("resident integer width");
            return Ok(
                integer_ratio(&value, &denominator)?.ln() + (bits as f64) * std::f64::consts::LN_2
            );
        }
        let value = self.float()?;
        if value <= 0. {
            return Err(value_error());
        }
        Ok(value.ln())
    }
    pub(super) fn ceil(&self) -> Result<Self> {
        if let Some(value) = self.integer() {
            return Ok(value.into());
        }
        let value = self.float()?;
        if value.is_nan() {
            return Err(value_error());
        }
        if value.is_infinite() {
            return Err(failure_kind(
                ErrorKind::Overflow,
                "cannot convert infinity to integer",
            ));
        }
        Ok(Self::Integer(
            format!("{:.0}", value.ceil()).parse().unwrap(),
        ))
    }
    pub(super) fn truncate(&self) -> Result<BigInt> {
        if let Some(value) = self.integer() {
            return Ok(value);
        }
        let value = self.float()?;
        if value.is_nan() {
            return Err(value_error());
        }
        if value.is_infinite() {
            return Err(failure_kind(
                ErrorKind::Overflow,
                "cannot convert infinity to integer",
            ));
        }
        Ok(format!("{:.0}", value.trunc()).parse().unwrap())
    }
    pub(super) fn power(&self, other: &Self) -> Result<Self> {
        if let (Some(base), Some(exponent)) = (self.integer(), other.integer())
            && exponent.sign() != Sign::Minus
        {
            if exponent == BigInt::from(0) {
                return Ok(1.into());
            }
            if base == BigInt::from(0) || base == BigInt::from(1) {
                return Ok(base.into());
            }
            if base == BigInt::from(-1) {
                return Ok(if (&exponent & BigInt::from(1)) == BigInt::from(0) {
                    1
                } else {
                    -1
                }
                .into());
            }
            let mut exponent = exponent;
            let mut base = base;
            let mut value = BigInt::from(1);
            while exponent != BigInt::from(0) {
                if (&exponent & BigInt::from(1)) != BigInt::from(0) {
                    value *= &base;
                }
                exponent >>= 1;
                if exponent != BigInt::from(0) {
                    base = &base * &base;
                }
            }
            return Ok(value.into());
        }
        let base = self.float()?;
        let exponent = other.float()?;
        if exponent == 0. {
            return Ok(Self::Float(1.));
        }
        if base == 0. && exponent.is_finite() && exponent < 0. {
            return Err(zero_division());
        }
        if base.is_finite() && base < 0. && exponent.is_finite() && exponent.fract() != 0. {
            // Python produces a complex value here, then circuit timeout's
            // min(complex, maximum) raises TypeError before drawing jitter.
            return Err(type_error());
        }
        let value = base.powf(exponent);
        if value.is_infinite() && base.is_finite() && exponent.is_finite() {
            return Err(failure_kind(ErrorKind::Overflow, "floating power overflow"));
        }
        Ok(Self::Float(value))
    }
}

fn int_float_cmp(integer: &BigInt, float: f64) -> Option<Ordering> {
    if float.is_nan() {
        return None;
    }
    if float == f64::INFINITY {
        return Some(Ordering::Less);
    }
    if float == f64::NEG_INFINITY {
        return Some(Ordering::Greater);
    }
    let truncated: BigInt = format!("{:.0}", float.trunc()).parse().unwrap();
    Some(match integer.cmp(&truncated) {
        Ordering::Equal if float.fract() > 0. => Ordering::Less,
        Ordering::Equal if float.fract() < 0. => Ordering::Greater,
        ordering => ordering,
    })
}

// Round a Python int/int quotient once, including ties and subnormal results.
// This avoids overflowing individually converted operands or double rounding.
fn integer_ratio(left: &BigInt, right: &BigInt) -> Result<f64> {
    if right == &BigInt::from(0) {
        return Err(zero_division());
    }
    let negative = (left.sign() == Sign::Minus) != (right.sign() == Sign::Minus);
    if left == &BigInt::from(0) {
        return Ok(if negative { -0. } else { 0. });
    }
    let numerator = left.magnitude();
    let denominator = right.magnitude();
    let mut exponent = i128::from(numerator.bits()) - i128::from(denominator.bits());
    let below = if exponent >= 0 {
        numerator < &(denominator << usize::try_from(exponent).expect("resident integer width"))
    } else {
        &(numerator << usize::try_from(-exponent).expect("resident integer width")) < denominator
    };
    if below {
        exponent -= 1;
    }
    if exponent > 1023 {
        return Err(failure_kind(
            ErrorKind::Overflow,
            "integer division result too large for a float",
        ));
    }
    if exponent < -1075 {
        return Ok(if negative { -0. } else { 0. });
    }
    let scale = (exponent - 52).max(-1074) as i32;
    let (numerator, denominator) = if scale <= 0 {
        (numerator << (-scale as usize), denominator.clone())
    } else {
        (numerator.clone(), denominator << (scale as usize))
    };
    let mut quotient = &numerator / &denominator;
    let remainder = &numerator % &denominator;
    let comparison = (&remainder << 1usize).cmp(&denominator);
    if comparison == Ordering::Greater
        || (comparison == Ordering::Equal && (&quotient & BigUint::from(1u8)) != BigUint::from(0u8))
    {
        quotient += BigUint::from(1u8);
    }
    let value = quotient.to_u64_digits().first().copied().unwrap_or(0) as f64;
    let value = if scale < -1022 {
        value * f64::from_bits(1u64 << (scale + 1074))
    } else {
        value * 2f64.powi(scale)
    };
    if value.is_infinite() {
        return Err(failure_kind(
            ErrorKind::Overflow,
            "integer division result too large for a float",
        ));
    }
    Ok(if negative { -value } else { value })
}

fn type_error() -> super::Error {
    failure_kind(ErrorKind::Type, "unsupported circuit numeric operands")
}
fn value_error() -> super::Error {
    failure_kind(ErrorKind::Value, "invalid circuit numeric value")
}
fn zero_division() -> super::Error {
    failure_kind(ErrorKind::ZeroDivision, "circuit division by zero")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_integer_division_matches_python_rounding_boundaries() {
        let rows: Value =
            serde_json::from_str(include_str!("../../tests/circuit_ratio_source.json")).unwrap();
        for row in rows.as_array().unwrap() {
            let a: BigInt = row["a"].as_str().unwrap().parse().unwrap();
            let b: BigInt = row["b"].as_str().unwrap().parse().unwrap();
            match integer_ratio(&a, &b) {
                Ok(value) => assert_eq!(
                    format!("{:016x}", value.to_bits()),
                    row["bits"].as_str().unwrap()
                ),
                Err(error) => assert_eq!(
                    match error.kind() {
                        ErrorKind::ZeroDivision => "ZeroDivisionError",
                        ErrorKind::Overflow => "OverflowError",
                        _ => "unexpected",
                    },
                    row["error"].as_str().unwrap()
                ),
            }
        }
    }
}

#[cfg(test)]
mod temporal_tests {
    use super::*;
    use crate::{
        circuits::CircuitBreaker,
        policy::{Format, Policy},
    };
    use serde_json::json;

    fn configured(source: &str, format: Format) -> CircuitBreaker {
        let policy = Policy::parse(source, format).unwrap();
        let circuit = CircuitBreaker::new();
        circuit.apply_policy_config(&policy).unwrap();
        circuit
    }
    fn yaml_operand(value: &str) -> CircuitValue {
        configured(
            &format!("addons:\n  circuit_breaker:\n    timeout_seconds: {value}\n"),
            Format::Yaml,
        )
        .settings()
        .unwrap()
        .timeout_seconds
    }

    #[test]
    fn temporal_types_remain_opaque_until_the_source_operation_consumes_them() {
        for value in [
            "2001-02-03",
            "2001-02-03T04:05:06Z",
            "[2001-02-03]",
            "{key: 2001-02-03}",
            "{2001-02-03: value}",
        ] {
            let operand = yaml_operand(value);
            assert!(operand.annotated().is_some());
            assert!(operand.truthy());
            assert_eq!(operand, operand.clone());
            assert_eq!(format!("{operand:?}"), "<non-numeric circuit field>");
            assert_eq!(operand.float().unwrap_err().kind(), ErrorKind::Type);
            assert_eq!(
                operand.compare(&1.into()).unwrap_err().kind(),
                ErrorKind::Type
            );
            assert_eq!(
                operand.render_json(false).unwrap_err().kind(),
                ErrorKind::Type
            );
            assert!(serde_json::to_value(&operand).is_err());
        }
        let time = configured(
            "[addons.circuit_breaker]\ntimeout_seconds = 00:00:00\n",
            Format::Toml,
        )
        .settings()
        .unwrap()
        .timeout_seconds;
        assert!(
            time.truthy(),
            "Python datetime.time is truthy even at midnight"
        );
        assert_eq!(time.render_json(false).unwrap_err().kind(), ErrorKind::Type);

        for value in [
            "'2001-02-03'",
            "{yaml_date: '2001-02-03'}",
            "{'2001-02-03': value}",
            "{nested: {yaml_date: '2001-02-03'}}",
            "[]",
            "{}",
        ] {
            let ordinary = yaml_operand(value);
            assert!(ordinary.annotated().is_none());
            assert!(ordinary.render_json(false).is_ok());
            assert_ne!(ordinary, yaml_operand("2001-02-03"));
        }
        assert!(!yaml_operand("[]").truthy());
        assert!(!yaml_operand("{}").truthy());
    }

    #[test]
    fn temporal_equality_uses_provenance_instead_of_storage_strings_or_keys() {
        assert_eq!(
            yaml_operand("2001-02-03T04:05:06Z"),
            yaml_operand("2001-02-03T05:05:06+01:00")
        );
        assert_ne!(
            yaml_operand("2001-02-03"),
            yaml_operand("2001-02-03T00:00:00")
        );
        assert_ne!(yaml_operand("2001-02-03"), yaml_operand("2001-02-04"));
        assert_eq!(
            yaml_operand("[{v: 2001-02-03T04:05:06Z}]"),
            yaml_operand("[{v: 2001-02-03T05:05:06+01:00}]")
        );
        assert_ne!(yaml_operand("[2001-02-03]"), yaml_operand("['2001-02-03']"));
        assert_eq!(
            yaml_operand("{2001-02-03: actual, '2001-02-03': quoted}"),
            yaml_operand("{'2001-02-03': quoted, 2001-02-03: actual}")
        );
        assert_ne!(
            yaml_operand("{2001-02-03: actual}"),
            yaml_operand("{'2001-02-03': actual}")
        );
        assert_ne!(
            yaml_operand("{2001-02-03: actual}"),
            yaml_operand("{2001-02-04: actual}")
        );
    }

    #[test]
    fn reached_json_failure_has_no_partial_output_or_file_publication() {
        let circuit = configured(
            "addons:\n  circuit_breaker:\n    timeout_seconds: 2001-02-03\n",
            Format::Yaml,
        );
        let stats = circuit.stats_document(true, 100., &mut || 0.5).unwrap();
        let mut output = String::from("prior bytes");
        assert_eq!(
            stats
                .value
                .write_json(&mut output, false)
                .unwrap_err()
                .kind(),
            ErrorKind::Type
        );
        assert_eq!(output, "prior bytes");
        assert_eq!(
            circuit.stats(true, 100., &mut || 0.5).unwrap_err().kind(),
            ErrorKind::Type
        );
        let settings = circuit.settings().unwrap();
        let duration = settings
            .calculate_timeout(0, &mut || panic!("zero streak bypasses arithmetic"))
            .unwrap();
        assert_eq!(duration, settings.timeout_seconds);
        assert_eq!(
            duration.render_json(true).unwrap_err().kind(),
            ErrorKind::Type
        );

        let state = CircuitValue::Object(
            [(
                "states".into(),
                CircuitValue::Object(
                    [(
                        "api".into(),
                        CircuitValue::Object(
                            [
                                ("state".into(), json!("closed").into()),
                                ("metadata".into(), duration),
                            ]
                            .into(),
                        ),
                    )]
                    .into(),
                ),
            )]
            .into(),
        );
        circuit.restore_document(&state, 100., &mut || 0.5).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        std::fs::write(&path, b"prior file").unwrap();
        assert_eq!(
            circuit.save_file(&path, 100.).unwrap_err().kind(),
            ErrorKind::Type
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"prior file");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        assert_eq!(
            CircuitValue::parse_json("[NaN, Infinity, -Infinity]")
                .unwrap()
                .render_json(false)
                .unwrap(),
            "[NaN, Infinity, -Infinity]"
        );
    }
}

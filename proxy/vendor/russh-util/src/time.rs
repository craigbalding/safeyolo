#[cfg(not(target_arch = "wasm32"))]
pub use std::time::Instant;

#[cfg(target_arch = "wasm32")]
pub use wasm::Instant;

#[cfg(any(target_arch = "wasm32", test))]
mod wasm {
    #[derive(Debug, Clone, Copy)]
    pub struct Instant {
        inner: web_time::SystemTime,
    }

    #[cfg(test)]
    mod tests {
        use super::Instant;
        use std::time::Duration;

        #[test]
        fn wall_clock_duration_is_preserved() {
            let earlier = Instant {
                inner: web_time::UNIX_EPOCH,
            };
            let later = Instant {
                inner: earlier.inner + Duration::from_millis(1234),
            };
            assert_eq!(later.duration_since(earlier), Duration::from_millis(1234));
            assert_eq!(earlier.duration_since(earlier), Duration::ZERO);
            let _ = Instant::now();
        }

        #[test]
        #[should_panic(expected = "Duration is negative")]
        fn backwards_wall_clock_still_refuses_a_negative_duration() {
            let earlier = Instant {
                inner: web_time::UNIX_EPOCH,
            };
            let later = Instant {
                inner: earlier.inner + Duration::from_millis(1),
            };
            earlier.duration_since(later);
        }
    }

    impl Instant {
        pub fn now() -> Self {
            Instant {
                inner: web_time::SystemTime::now(),
            }
        }

        pub fn duration_since(&self, earlier: Instant) -> std::time::Duration {
            self.inner
                .duration_since(earlier.inner)
                .expect("Duration is negative")
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    #[test]
    fn native_instant_is_the_standard_library_type() {
        let _: std::time::Instant = super::Instant::now();
    }
}

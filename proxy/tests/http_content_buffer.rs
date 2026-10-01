use safeyolo_proxy::http_content::{BUFFERED_BODY_THRESHOLD, BufferedContent};

#[test]
fn empty_buffered_content_is_distinct_from_absent_streamed_content() {
    for length in [None, Some(0), Some(BUFFERED_BODY_THRESHOLD as u64)] {
        let mut content = BufferedContent::new(length, false);
        content.push(b"");
        assert!(!content.is_streamed());
        assert!(content.into_content().unwrap().is_empty());
    }
    for (length, streamed) in [
        (None, true),
        (Some(0), true),
        (Some(BUFFERED_BODY_THRESHOLD as u64), true),
        (Some(BUFFERED_BODY_THRESHOLD as u64 + 1), false),
        (Some(u64::MAX), false),
    ] {
        let mut content = BufferedContent::new(length, streamed);
        assert!(content.is_streamed());
        content.push(b"synthetic bytes");
        content.push(b"");
        assert!(content.is_streamed());
        assert!(content.into_content().is_none());
    }
}

#[test]
fn exact_threshold_across_frames_preserves_original_encoded_bytes() {
    let mut encoded = vec![b'x'; BUFFERED_BODY_THRESHOLD];
    encoded[..4].copy_from_slice(&[0x1f, 0x8b, 0xff, 0x00]);
    for length in [None, Some(BUFFERED_BODY_THRESHOLD as u64)] {
        let mut content = BufferedContent::new(length, false);
        for frame in encoded.chunks(16_381) {
            content.push(frame);
            assert!(!content.is_streamed());
        }
        content.push(b"");
        assert!(!content.is_streamed());
        // Encoded bytes are retained without interpretation or validation.
        assert_eq!(content.into_content().unwrap().as_slice(), encoded);
    }
}

#[test]
fn crossing_threshold_discards_prior_bytes_and_cannot_resume_buffering() {
    let frame = vec![b'x'; BUFFERED_BODY_THRESHOLD];
    for length in [None, Some(0), Some(BUFFERED_BODY_THRESHOLD as u64)] {
        let mut content = BufferedContent::new(length, false);
        content.push(&frame);
        assert!(!content.is_streamed());
        content.push(b"y");
        assert!(content.is_streamed());
        content.push(b"");
        content.push(b"later frame");
        assert!(content.is_streamed());
        assert!(content.into_content().is_none());
    }
}

#[test]
fn single_oversized_frame_also_makes_content_absent() {
    let mut content = BufferedContent::new(None, false);
    content.push(&vec![b'x'; BUFFERED_BODY_THRESHOLD + 1]);
    assert!(content.is_streamed());
    assert!(content.into_content().is_none());
}

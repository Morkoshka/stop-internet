//! Just enough of a PNG encoder for the largest image of the icon.
//!
//! Each row is filtered by the difference to the pixel on the left (the
//! "Sub" filter), so the flat fill, the rim, the sign and the transparent
//! background turn into long runs of zeros. Deflate then only codes runs
//! of a repeated byte, as matches at distance 1, with the fixed Huffman
//! codes. That brings the 256 KiB of pixels of the shield down to about
//! 14 KiB without a general compressor.

/// A PNG of `size` × `size` pixels, `0xAARRGGBB` with straight alpha, top
/// row first.
pub(crate) fn encode(size: u32, pixels: &[u32]) -> Vec<u8> {
    let mut rows = Vec::with_capacity(pixels.len() * 4 + size as usize);
    for row in pixels.chunks(size as usize) {
        // Filter type 1, Sub.
        rows.push(1);
        let mut left = [0u8; 4];
        for &pixel in row {
            let [alpha, red, green, blue] = pixel.to_be_bytes();
            let rgba = [red, green, blue, alpha];
            for (byte, before) in rgba.iter().zip(left) {
                rows.push(byte.wrapping_sub(before));
            }
            left = rgba;
        }
    }

    let mut header = Vec::with_capacity(13);
    header.extend(size.to_be_bytes());
    header.extend(size.to_be_bytes());
    // 8 bits per channel, red green blue and alpha, deflate, the standard
    // filters, no interlacing.
    header.extend([8, 6, 0, 0, 0]);

    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut png, b"IHDR", &header);
    chunk(&mut png, b"IDAT", &zlib(&rows));
    chunk(&mut png, b"IEND", &[]);
    png
}

fn chunk(png: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    let length = u32::try_from(data.len()).expect("a chunk is smaller than 4 GiB");
    png.extend(length.to_be_bytes());
    let start = png.len();
    png.extend(kind);
    png.extend(data);
    let crc = crc32(&png[start..]);
    png.extend(crc.to_be_bytes());
}

/// A zlib stream: the header (deflate with a 32 KiB window, no dictionary),
/// the deflate data and the Adler-32 checksum of `data`.
fn zlib(data: &[u8]) -> Vec<u8> {
    let mut stream = vec![0x78, 0x01];
    stream.extend(deflate(data));
    stream.extend(adler32(data).to_be_bytes());
    stream
}

/// Base lengths of the length codes 257 to 285 and their extra bits.
const LENGTHS: [(u16, u8); 29] = [
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 1),
    (13, 1),
    (15, 1),
    (17, 1),
    (19, 2),
    (23, 2),
    (27, 2),
    (31, 2),
    (35, 3),
    (43, 3),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 4),
    (115, 4),
    (131, 5),
    (163, 5),
    (195, 5),
    (227, 5),
    (258, 0),
];

/// Matches are 3 to 258 bytes long.
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;

/// One final deflate block with the fixed Huffman codes: literals, and
/// runs of the byte before as matches at distance 1.
fn deflate(data: &[u8]) -> Vec<u8> {
    let mut bits = Bits::default();
    // The last block; type 1, fixed codes.
    bits.put(1, 1);
    bits.put(1, 2);
    let mut at = 0;
    while at < data.len() {
        let run = match at.checked_sub(1) {
            Some(before) => data[at..]
                .iter()
                .take(MAX_MATCH)
                .take_while(|&&byte| byte == data[before])
                .count(),
            None => 0,
        };
        if run >= MIN_MATCH {
            let index = LENGTHS.partition_point(|&(base, _)| usize::from(base) <= run) - 1;
            let (base, extra) = LENGTHS[index];
            bits.symbol(257 + index as u16);
            bits.put(u32::try_from(run).unwrap() - u32::from(base), extra);
            // Distance code 0, distance 1: five zero bits.
            bits.put(0, 5);
            at += run;
        } else {
            bits.symbol(u16::from(data[at]));
            at += 1;
        }
    }
    // End of the block.
    bits.symbol(256);
    bits.finish()
}

/// Bits in the order of deflate: from the lowest bit of each byte.
#[derive(Debug, Default)]
struct Bits {
    bytes: Vec<u8>,
    pending: u32,
    count: u8,
}

impl Bits {
    /// The lowest `count` bits of `value`, lowest first.
    fn put(&mut self, value: u32, count: u8) {
        for bit in 0..count {
            self.pending |= ((value >> bit) & 1) << self.count;
            self.count += 1;
            if self.count == 8 {
                self.bytes.push(self.pending as u8);
                self.pending = 0;
                self.count = 0;
            }
        }
    }

    /// A literal or length symbol in its fixed Huffman code, which goes
    /// out highest bit first.
    fn symbol(&mut self, symbol: u16) {
        let (code, length) = match symbol {
            0..=143 => (0x30 + u32::from(symbol), 8),
            144..=255 => (0x190 + u32::from(symbol - 144), 9),
            256..=279 => (u32::from(symbol - 256), 7),
            _ => (0xc0 + u32::from(symbol - 280), 8),
        };
        for bit in (0..length).rev() {
            self.put(code >> bit, 1);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.count > 0 {
            self.bytes.push(self.pending as u8);
        }
        self.bytes
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn adler32(bytes: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in bytes {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Color, draw};

    /// Reads back what [`deflate`] writes: one block with the fixed codes.
    /// Distance codes beyond 3 never occur here and are not decoded.
    fn inflate(stream: &[u8]) -> Vec<u8> {
        let mut at = 0usize;
        let mut bit = |count: u32| -> u32 {
            (0..count).fold(0, |value, index| {
                let one = (stream[at / 8] >> (at % 8)) & 1;
                at += 1;
                value | (u32::from(one) << index)
            })
        };
        assert_eq!(bit(1), 1, "the last block");
        assert_eq!(bit(2), 1, "fixed codes");
        let mut out = Vec::new();
        loop {
            // Huffman codes come highest bit first.
            let mut code = 0;
            let mut length = 0;
            let symbol = loop {
                code = (code << 1) | bit(1);
                length += 1;
                match (length, code) {
                    (7, 0..=23) => break 256 + code,
                    (8, 0x30..=0xbf) => break code - 0x30,
                    (8, 0xc0..=0xc7) => break 280 + code - 0xc0,
                    (9, 0x190..=0x1ff) => break 144 + code - 0x190,
                    (9, _) => panic!("no such code"),
                    _ => {}
                }
            };
            match symbol {
                0..=255 => out.push(symbol as u8),
                256 => return out,
                _ => {
                    let (base, extra) = LENGTHS[(symbol - 257) as usize];
                    let length = u32::from(base) + bit(u32::from(extra));
                    let mut distance = 0;
                    for _ in 0..5 {
                        distance = (distance << 1) | bit(1);
                    }
                    assert!(distance < 4, "distance code {distance}");
                    let distance = distance as usize + 1;
                    for _ in 0..length {
                        out.push(out[out.len() - distance]);
                    }
                }
            }
        }
    }

    #[test]
    fn a_single_letter_is_coded_like_zlib_does() {
        // zlib.compress(b"a") is 78 9c 4b 04 00 00 62 00 62.
        assert_eq!(deflate(b"a"), [0x4b, 0x04, 0x00]);
        assert_eq!(adler32(b"a"), 0x0062_0062);
    }

    #[test]
    fn the_checksums_match_known_values() {
        assert_eq!(crc32(b"IEND"), 0xae42_6082);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
    }

    #[test]
    fn runs_of_every_length_come_back() {
        let mut data = Vec::new();
        for length in 1..600 {
            data.extend(std::iter::repeat_n((length % 251) as u8, length));
        }
        assert_eq!(inflate(&deflate(&data)), data);
        assert!(deflate(&data).len() < data.len() / 20);
    }

    #[test]
    fn the_image_comes_back_from_the_png() {
        let size = 256;
        let pixels = draw(size, Color::Green);
        let png = encode(size, &pixels);
        assert!(png.len() < 32 * 1024, "{} bytes", png.len());

        // Signature, then IHDR, IDAT and IEND with their checksums.
        assert_eq!(png[..8], *b"\x89PNG\r\n\x1a\n");
        let mut chunks = Vec::new();
        let mut at = 8;
        while at < png.len() {
            let length = u32::from_be_bytes(png[at..at + 4].try_into().unwrap()) as usize;
            let body = &png[at + 4..at + 8 + length];
            let crc =
                u32::from_be_bytes(png[at + 8 + length..at + 12 + length].try_into().unwrap());
            assert_eq!(crc32(body), crc);
            chunks.push((body[..4].to_vec(), body[4..].to_vec()));
            at += 12 + length;
        }
        let kinds: Vec<&[u8]> = chunks.iter().map(|(kind, _)| kind.as_slice()).collect();
        assert_eq!(kinds, [b"IHDR".as_slice(), b"IDAT", b"IEND"]);
        assert_eq!(chunks[0].1, [0, 0, 1, 0, 0, 0, 1, 0, 8, 6, 0, 0, 0]);

        let stream = &chunks[1].1;
        assert_eq!(stream[..2], [0x78, 0x01]);
        assert_eq!(u16::from_be_bytes([stream[0], stream[1]]) % 31, 0);
        let rows = inflate(&stream[2..stream.len() - 4]);
        let adler = u32::from_be_bytes(stream[stream.len() - 4..].try_into().unwrap());
        assert_eq!(adler32(&rows), adler);

        let stride = 1 + 4 * size as usize;
        assert_eq!(rows.len(), stride * size as usize);
        for (y, row) in rows.chunks(stride).enumerate() {
            assert_eq!(row[0], 1, "filter of row {y}");
            let mut left = [0u8; 4];
            for (x, filtered) in row[1..].chunks(4).enumerate() {
                let rgba: [u8; 4] = std::array::from_fn(|i| filtered[i].wrapping_add(left[i]));
                let [red, green, blue, alpha] = rgba;
                let expected = pixels[y * size as usize + x];
                assert_eq!(
                    u32::from_be_bytes([alpha, red, green, blue]),
                    expected,
                    "({x}, {y})"
                );
                left = rgba;
            }
        }
    }
}

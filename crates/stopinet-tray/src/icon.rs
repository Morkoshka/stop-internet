//! Pixels of the status icons, drawn in code so that the repository holds
//! no binary images: a filled circle in the color of the state with a
//! darker rim, smoothed at the edge, on a transparent background.

use crate::view::Color;

impl Color {
    /// Red, green and blue.
    pub fn rgb(self) -> [u8; 3] {
        match self {
            Self::Green => [0x2e, 0xa0, 0x43],
            Self::Red => [0xd1, 0x24, 0x2f],
            Self::Grey => [0x8c, 0x95, 0x9f],
        }
    }
}

/// Subsamples per pixel along each axis, for the smooth edge.
const SAMPLES: u32 = 4;

/// Pixels of a `size` × `size` icon, top row first, as `0xAARRGGBB` with
/// straight alpha.
pub fn disc(size: u32, color: Color) -> Vec<u32> {
    let [r, g, b] = color.rgb();
    let fill = [r, g, b].map(f32::from);
    let rim = fill.map(|c| c * 0.65);

    let center = size as f32 / 2.0;
    let outer = center - 0.5;
    let inner = outer - (size as f32 / 16.0).max(1.0);

    let mut pixels = Vec::with_capacity((size * size) as usize);
    for y in 0..size {
        for x in 0..size {
            let (mut in_disc, mut in_fill) = (0u32, 0u32);
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let px = x as f32 + (sx as f32 + 0.5) / SAMPLES as f32 - center;
                    let py = y as f32 + (sy as f32 + 0.5) / SAMPLES as f32 - center;
                    let distance = (px * px + py * py).sqrt();
                    in_disc += u32::from(distance < outer);
                    in_fill += u32::from(distance < inner);
                }
            }
            if in_disc == 0 {
                pixels.push(0);
                continue;
            }
            let alpha = (in_disc * 255 / (SAMPLES * SAMPLES)) as u8;
            let share = in_fill as f32 / in_disc as f32;
            let [r, g, b] = [0, 1, 2].map(|i| (rim[i] + (fill[i] - rim[i]) * share).round() as u8);
            pixels.push(u32::from_be_bytes([alpha, r, g, b]));
        }
    }
    pixels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argb(pixel: u32) -> [u8; 4] {
        pixel.to_be_bytes()
    }

    #[test]
    fn has_one_pixel_per_point() {
        for size in [16, 20, 24, 32] {
            assert_eq!(disc(size, Color::Green).len(), (size * size) as usize);
        }
    }

    #[test]
    fn corners_are_transparent_and_the_center_is_the_color() {
        let size = 32;
        let pixels = disc(size, Color::Red);
        for corner in [0, size - 1, size * (size - 1), size * size - 1] {
            assert_eq!(pixels[corner as usize], 0);
        }
        let [alpha, r, g, b] = argb(pixels[(size * size / 2 + size / 2) as usize]);
        assert_eq!(alpha, 255);
        assert_eq!([r, g, b], Color::Red.rgb());
    }

    #[test]
    fn the_rim_is_darker_than_the_fill() {
        let size = 32;
        let pixels = disc(size, Color::Grey);
        let row = size / 2;
        let edge = (0..size)
            .map(|x| argb(pixels[(row * size + x) as usize]))
            .find(|p| p[0] == 255)
            .unwrap();
        assert!(edge[1] < Color::Grey.rgb()[0], "{edge:?}");
    }

    #[test]
    fn is_symmetric() {
        let size = 24;
        let pixels = disc(size, Color::Green);
        for y in 0..size {
            for x in 0..size {
                let mirrored = size - 1 - x;
                assert_eq!(
                    pixels[(y * size + x) as usize],
                    pixels[(y * size + mirrored) as usize]
                );
            }
        }
    }
}

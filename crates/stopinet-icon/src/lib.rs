//! The shield of stop-internet, drawn in code so that the repository holds
//! no binary images: a shield in the color of the state with a darker rim
//! and a white sign, smoothed at the edges, on a transparent background.
//!
//! - [`draw`] gives the pixels, for the status icon of the tray.
//! - [`ico`] gives an `.ico` file, for the installer.
//! - [`embed`], called from the build script of a program, puts the green
//!   shield and the version into the program as Windows resources, for
//!   Explorer and Task Manager.
//!
//! The shape and the sign tell the states apart even where colors do not,
//! for example next to the round voice indicator of a chat program:
//! a check mark when protected and working, a cross when blocked, a dash
//! when protection is off.
//!
//! The pictures in `docs/images` are SVG versions of the same icons. A test
//! builds them from the constants here and fails when they differ; running
//! the tests with `STOPINET_UPDATE_PICTURES=1` writes them anew.

#![forbid(unsafe_code)]

mod ico;
mod png;
mod resource;

use std::f32::consts::FRAC_PI_2;

pub use ico::ico;
pub use resource::embed;

/// Color of the icon, after the state of the protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    /// Protected, and the internet works through the VPN client.
    Green,
    /// Blocked: the tunnel is down in tunnel-only mode, or the service
    /// cannot be asked.
    Red,
    /// Protection is off.
    Grey,
}

impl Color {
    /// Red, green and blue.
    pub fn rgb(self) -> [u8; 3] {
        match self {
            Self::Green => [0x2e, 0xa0, 0x43],
            Self::Red => [0xd1, 0x24, 0x2f],
            Self::Grey => [0x8c, 0x95, 0x9f],
        }
    }

    /// Strokes of the sign, in the unit square of the icon.
    fn sign(self) -> &'static [Segment] {
        match self {
            Self::Green => &[((0.31, 0.46), (0.45, 0.60)), ((0.45, 0.60), (0.69, 0.33))],
            Self::Red => &[((0.36, 0.30), (0.64, 0.58)), ((0.64, 0.30), (0.36, 0.58))],
            Self::Grey => &[((0.33, 0.44), (0.67, 0.44))],
        }
    }
}

type Point = (f32, f32);
type Segment = (Point, Point);

/// Subsamples per pixel along each axis, for the smooth edges.
const SAMPLES: u32 = 4;

/// Edges of the shield in the unit square: sides, top, where the sides
/// start to narrow, and the tip.
const LEFT: f32 = 0.13;
const RIGHT: f32 = 0.87;
const TOP: f32 = 0.07;
const WAIST: f32 = 0.50;
const TIP: f32 = 0.96;
const CORNER: f32 = 0.12;

/// Half the width of a stroke of the sign.
const STROKE: f32 = 0.068;

const WHITE: [f32; 3] = [255.0, 255.0, 255.0];

/// Pixels of a `size` × `size` icon, top row first, as `0xAARRGGBB` with
/// straight alpha.
pub fn draw(size: u32, color: Color) -> Vec<u32> {
    let fill = color.rgb().map(f32::from);
    let rim = fill.map(|c| c * 0.65);
    let rim_width = (1.0 / 16.0_f32).max(1.0 / size as f32);
    let sign = color.sign();

    let mut pixels = Vec::with_capacity((size * size) as usize);
    for y in 0..size {
        for x in 0..size {
            let mut sum = [0.0f32; 3];
            let mut covered = 0u32;
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let u = (x as f32 + (sx as f32 + 0.5) / SAMPLES as f32) / size as f32;
                    let v = (y as f32 + (sy as f32 + 0.5) / SAMPLES as f32) / size as f32;
                    if !in_shield(u, v) {
                        continue;
                    }
                    covered += 1;
                    let paint = if on_sign(sign, (u, v)) {
                        WHITE
                    } else if near_edge(u, v, rim_width) {
                        rim
                    } else {
                        fill
                    };
                    for (total, channel) in sum.iter_mut().zip(paint) {
                        *total += channel;
                    }
                }
            }
            if covered == 0 {
                pixels.push(0);
                continue;
            }
            let alpha = (covered * 255 / (SAMPLES * SAMPLES)) as u8;
            let [r, g, b] = sum.map(|total| (total / covered as f32).round() as u8);
            pixels.push(u32::from_be_bytes([alpha, r, g, b]));
        }
    }
    pixels
}

/// A shield: straight sides with rounded top corners down to the waist,
/// then curving in to a point.
fn in_shield(u: f32, v: f32) -> bool {
    if !(TOP..=TIP).contains(&v) {
        return false;
    }
    let half = (RIGHT - LEFT) / 2.0;
    let dx = (u - 0.5).abs();
    if v > WAIST {
        let t = (v - WAIST) / (TIP - WAIST);
        return dx <= half * (t * FRAC_PI_2).cos();
    }
    if dx > half {
        return false;
    }
    let (corner_x, corner_y) = (half - CORNER, TOP + CORNER);
    if v < corner_y && dx > corner_x {
        let (ex, ey) = (dx - corner_x, v - corner_y);
        return ex * ex + ey * ey <= CORNER * CORNER;
    }
    true
}

/// Whether the point is within `width` of the outline.
fn near_edge(u: f32, v: f32, width: f32) -> bool {
    const DIRECTIONS: [(f32, f32); 8] = [
        (1.0, 0.0),
        (-1.0, 0.0),
        (0.0, 1.0),
        (0.0, -1.0),
        (0.7, 0.7),
        (-0.7, 0.7),
        (0.7, -0.7),
        (-0.7, -0.7),
    ];
    DIRECTIONS
        .iter()
        .any(|(du, dv)| !in_shield(u + du * width, v + dv * width))
}

fn on_sign(sign: &[Segment], point: Point) -> bool {
    sign.iter()
        .any(|&(a, b)| distance_to_segment(point, a, b) <= STROKE)
}

fn distance_to_segment(p: Point, a: Point, b: Point) -> f32 {
    let (abx, aby) = (b.0 - a.0, b.1 - a.1);
    let (apx, apy) = (p.0 - a.0, p.1 - a.1);
    let length = abx * abx + aby * aby;
    let t = ((apx * abx + apy * aby) / length).clamp(0.0, 1.0);
    let (dx, dy) = (apx - abx * t, apy - aby * t);
    (dx * dx + dy * dy).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    const COLORS: [Color; 3] = [Color::Green, Color::Red, Color::Grey];

    fn argb(pixel: u32) -> [u8; 4] {
        pixel.to_be_bytes()
    }

    fn at(pixels: &[u32], size: u32, u: f32, v: f32) -> [u8; 4] {
        let (x, y) = ((u * size as f32) as u32, (v * size as f32) as u32);
        argb(pixels[(y * size + x) as usize])
    }

    #[test]
    fn has_one_pixel_per_point() {
        for size in [16, 20, 24, 32] {
            for color in COLORS {
                assert_eq!(draw(size, color).len(), (size * size) as usize);
            }
        }
    }

    #[test]
    fn corners_and_the_sides_of_the_tip_are_transparent() {
        let size = 32;
        for color in COLORS {
            let pixels = draw(size, color);
            for corner in [0, size - 1, size * (size - 1), size * size - 1] {
                assert_eq!(pixels[corner as usize], 0, "{color:?}");
            }
            assert_eq!(at(&pixels, size, 0.15, 0.92)[0], 0, "{color:?}");
            assert_eq!(at(&pixels, size, 0.85, 0.92)[0], 0, "{color:?}");
        }
    }

    #[test]
    fn the_body_has_the_color_and_the_sign_is_white() {
        let size = 32;
        for color in COLORS {
            let pixels = draw(size, color);
            let [alpha, r, g, b] = at(&pixels, size, 0.25, 0.25);
            assert_eq!(alpha, 255, "{color:?}");
            assert_eq!([r, g, b], color.rgb(), "{color:?}");
            let (from, to) = color.sign()[0];
            let middle = ((from.0 + to.0) / 2.0, (from.1 + to.1) / 2.0);
            assert_eq!(at(&pixels, size, middle.0, middle.1), [255; 4], "{color:?}");
        }
    }

    #[test]
    fn the_rim_is_darker_than_the_fill() {
        let size = 32;
        let pixels = draw(size, Color::Grey);
        let row = size / 3;
        let edge = (0..size)
            .map(|x| argb(pixels[(row * size + x) as usize]))
            .find(|p| p[0] == 255)
            .unwrap();
        assert!(edge[1] < Color::Grey.rgb()[0], "{edge:?}");
    }

    #[test]
    fn the_three_states_look_different() {
        for size in [16, 32] {
            let icons = COLORS.map(|color| draw(size, color));
            let white = |pixels: &Vec<u32>| -> Vec<bool> {
                pixels.iter().map(|&p| argb(p)[1..] == [255; 3]).collect()
            };
            // The signs differ even with the colors taken away.
            assert_ne!(white(&icons[0]), white(&icons[1]));
            assert_ne!(white(&icons[1]), white(&icons[2]));
            assert_ne!(white(&icons[0]), white(&icons[2]));
        }
    }

    /// The icon as SVG, for the pictures in `docs/images`: the same shape,
    /// colors and signs, at 100 units per side. The curve from the waist to
    /// the tip is a cubic Bézier with the tangents of the cosine.
    fn svg(color: Color) -> String {
        let n = |value: f32| {
            let text = format!("{:.2}", value * 100.0);
            text.trim_end_matches('0').trim_end_matches('.').to_owned()
        };
        let hex = |rgb: [f32; 3]| {
            let [r, g, b] = rgb.map(|c| c.round() as u8);
            format!("#{r:02x}{g:02x}{b:02x}")
        };
        let half = (RIGHT - LEFT) / 2.0;
        let (rise, reach) = ((TIP - WAIST) / 3.0, half * FRAC_PI_2 / 3.0);
        let shield = format!(
            "M{} {}H{}A{r} {r} 0 0 1 {} {}V{}C{} {} {} {} 50 {}C{} {} {} {} {} {}V{}A{r} {r} 0 0 1 {} {}Z",
            n(LEFT + CORNER),
            n(TOP),
            n(RIGHT - CORNER),
            n(RIGHT),
            n(TOP + CORNER),
            n(WAIST),
            n(RIGHT),
            n(WAIST + rise),
            n(0.5 + reach),
            n(TIP - rise),
            n(TIP),
            n(0.5 - reach),
            n(TIP - rise),
            n(LEFT),
            n(WAIST + rise),
            n(LEFT),
            n(WAIST),
            n(TOP + CORNER),
            n(LEFT + CORNER),
            n(TOP),
            r = n(CORNER),
        );
        let sign: String = color
            .sign()
            .iter()
            .map(|(a, b)| format!("M{} {}L{} {}", n(a.0), n(a.1), n(b.0), n(b.1)))
            .collect();
        let fill = color.rgb().map(f32::from);
        let title = match color {
            Color::Green => "Protected",
            Color::Red => "Blocked",
            Color::Grey => "Protection off",
        };
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 100 100\" width=\"100\" height=\"100\">\n\
             <title>{title}</title>\n\
             <clipPath id=\"shield\"><path d=\"{shield}\"/></clipPath>\n\
             <path d=\"{shield}\" fill=\"{}\" stroke=\"{}\" stroke-width=\"{}\" clip-path=\"url(#shield)\"/>\n\
             <path d=\"{sign}\" fill=\"none\" stroke=\"#fff\" stroke-width=\"{}\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>\n\
             </svg>\n",
            hex(fill),
            hex(fill.map(|c| c * 0.65)),
            // The rim lies inside the outline; the clip cuts the outer half.
            n(2.0 / 16.0),
            n(2.0 * STROKE),
        )
    }

    #[test]
    fn the_pictures_in_the_docs_match_the_icons() {
        let pictures = [
            (
                Color::Green,
                "shield-green.svg",
                include_str!("../../../docs/images/shield-green.svg"),
            ),
            (
                Color::Red,
                "shield-red.svg",
                include_str!("../../../docs/images/shield-red.svg"),
            ),
            (
                Color::Grey,
                "shield-grey.svg",
                include_str!("../../../docs/images/shield-grey.svg"),
            ),
        ];
        let update = std::env::var_os("STOPINET_UPDATE_PICTURES").is_some();
        for (color, name, picture) in pictures {
            let expected = svg(color);
            if update {
                let path = format!("{}/../../docs/images/{name}", env!("CARGO_MANIFEST_DIR"));
                std::fs::write(path, &expected).unwrap();
                continue;
            }
            // Git may check the file out with CRLF line ends.
            assert_eq!(
                picture.replace("\r\n", "\n"),
                expected,
                "docs/images/{name} is out of date: run the tests with STOPINET_UPDATE_PICTURES=1"
            );
        }
    }

    #[test]
    fn the_cross_and_the_dash_are_symmetric() {
        let size = 24;
        for color in [Color::Red, Color::Grey] {
            let pixels = draw(size, color);
            for y in 0..size {
                for x in 0..size {
                    let mirrored = size - 1 - x;
                    assert_eq!(
                        pixels[(y * size + x) as usize],
                        pixels[(y * size + mirrored) as usize],
                        "{color:?}"
                    );
                }
            }
        }
    }
}

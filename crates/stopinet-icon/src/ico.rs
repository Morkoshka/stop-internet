//! The images of an icon, in an `.ico` file or in the directory of an icon
//! resource: the two hold the same images and differ only in how the
//! directory points to them.

use crate::{Color, draw, png};

/// Sizes of the images, in pixels: the small icons of Explorer, the
/// taskbar, the title bar and Task Manager at the usual display scales,
/// and 256 for the large views of Explorer, which scale it down.
const SIZES: [u32; 8] = [16, 20, 24, 32, 40, 48, 64, 256];

/// Size of `ICONDIR`, the header of both directories.
const HEADER: usize = 6;
/// Size of `ICONDIRENTRY`, an image in the directory of a file.
const FILE_ENTRY: usize = 16;

/// One image of an icon, as stored in a file or a resource.
#[derive(Debug)]
pub(crate) struct Image {
    pub size: u32,
    pub data: Vec<u8>,
}

/// The shield in `color` in every size: bitmaps for the small images, as
/// older parts of Windows expect, and PNG for 256 pixels, where a bitmap
/// would take 256 KiB.
pub(crate) fn images(color: Color) -> Vec<Image> {
    SIZES
        .iter()
        .map(|&size| {
            let pixels = draw(size, color);
            let data = if size >= 256 {
                png::encode(size, &pixels)
            } else {
                bitmap(size, &pixels)
            };
            Image { size, data }
        })
        .collect()
}

/// An `.ico` file of the shield in `color`.
pub fn ico(color: Color) -> Vec<u8> {
    let images = images(color);
    let mut file = header(images.len());
    let mut offset = HEADER + FILE_ENTRY * images.len();
    for image in &images {
        file.extend(entry(image));
        file.extend(u32_of(offset).to_le_bytes());
        offset += image.data.len();
    }
    for image in &images {
        file.extend(&image.data);
    }
    file
}

/// The directory of an icon resource (`RT_GROUP_ICON`). Instead of an
/// offset, each image is named by the ID of its own `RT_ICON` resource,
/// `first_id` and on.
pub(crate) fn group(images: &[Image], first_id: u16) -> Vec<u8> {
    let mut group = header(images.len());
    for (id, image) in (first_id..).zip(images) {
        group.extend(entry(image));
        group.extend(id.to_le_bytes());
    }
    group
}

/// `ICONDIR`: reserved, the type (1, an icon) and the number of images.
fn header(count: usize) -> Vec<u8> {
    let count = u16::try_from(count).expect("an icon holds at most 65535 images");
    [0, 1, count].iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// The fields that both directories have for an image: width and height
/// (0 means 256), no palette, a reserved byte, one plane, 32 bits per
/// pixel and the size of the data.
fn entry(image: &Image) -> Vec<u8> {
    let side = u8::try_from(image.size).unwrap_or(0);
    let mut entry = vec![side, side, 0, 0];
    entry.extend(1u16.to_le_bytes());
    entry.extend(32u16.to_le_bytes());
    entry.extend(u32_of(image.data.len()).to_le_bytes());
    entry
}

/// A bitmap as an icon stores it: `BITMAPINFOHEADER` with twice the
/// height, for the color and the mask, then the pixels bottom row first as
/// blue, green, red and alpha, then the mask. Windows draws by the alpha
/// channel; the mask, set where a pixel is fully transparent, is for
/// whatever ignores it.
fn bitmap(size: u32, pixels: &[u32]) -> Vec<u8> {
    let side = size as usize;
    let mask_row = side.div_ceil(32) * 4;
    let image_size = side * side * 4 + mask_row * side;

    let mut data = Vec::with_capacity(40 + image_size);
    data.extend(40u32.to_le_bytes());
    data.extend(size.to_le_bytes());
    data.extend((2 * size).to_le_bytes());
    data.extend(1u16.to_le_bytes());
    data.extend(32u16.to_le_bytes());
    // BI_RGB, the size of the image, then no resolution and no palette.
    data.extend(0u32.to_le_bytes());
    data.extend(u32_of(image_size).to_le_bytes());
    data.extend([0; 16]);

    for row in pixels.chunks(side).rev() {
        for &pixel in row {
            let [alpha, red, green, blue] = pixel.to_be_bytes();
            data.extend([blue, green, red, alpha]);
        }
    }
    for row in pixels.chunks(side).rev() {
        let mut bits = vec![0u8; mask_row];
        for (x, &pixel) in row.iter().enumerate() {
            if pixel >> 24 == 0 {
                bits[x / 8] |= 0x80 >> (x % 8);
            }
        }
        data.extend(bits);
    }
    data
}

fn u32_of(value: usize) -> u32 {
    u32::try_from(value).expect("an icon is smaller than 4 GiB")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_at(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([bytes[at], bytes[at + 1]])
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn the_file_points_to_every_image() {
        let file = ico(Color::Green);
        assert_eq!(&file[..HEADER], [0, 0, 1, 0, SIZES.len() as u8, 0]);
        let mut end = HEADER + FILE_ENTRY * SIZES.len();
        for (index, size) in SIZES.into_iter().enumerate() {
            let entry = &file[HEADER + FILE_ENTRY * index..][..FILE_ENTRY];
            let side = if size == 256 { 0 } else { size as u8 };
            assert_eq!(entry[..4], [side, side, 0, 0], "{size}");
            assert_eq!(u16_at(entry, 4), 1, "{size}");
            assert_eq!(u16_at(entry, 6), 32, "{size}");
            let (length, offset) = (u32_at(entry, 8) as usize, u32_at(entry, 12) as usize);
            // The images follow the directory, in its order, without gaps.
            assert_eq!(offset, end, "{size}");
            end += length;
            let data = &file[offset..offset + length];
            if size == 256 {
                assert!(data.starts_with(b"\x89PNG\r\n\x1a\n"));
            } else {
                assert_eq!(u32_at(data, 0), 40, "{size}");
                assert_eq!(u32_at(data, 4), size, "{size}");
                assert_eq!(u32_at(data, 8), 2 * size, "{size}");
            }
        }
        assert_eq!(end, file.len());
    }

    #[test]
    fn the_group_names_the_images_by_id() {
        let images = images(Color::Green);
        let group = group(&images, 7);
        assert_eq!(group.len(), HEADER + 14 * images.len());
        assert_eq!(u16_at(&group, 4), images.len() as u16);
        for (index, image) in images.iter().enumerate() {
            let entry = &group[HEADER + 14 * index..][..14];
            assert_eq!(u32_at(entry, 8) as usize, image.data.len());
            assert_eq!(u16_at(entry, 12), 7 + index as u16);
        }
    }

    #[test]
    fn the_bitmap_is_bottom_up_with_a_mask_of_the_transparent_pixels() {
        let size = 32;
        let pixels = draw(size, Color::Red);
        let data = bitmap(size, &pixels);
        let side = size as usize;
        assert_eq!(data.len(), 40 + side * side * 4 + 4 * side);
        let pixel = |x: usize, y: usize| {
            let at = 40 + ((side - 1 - y) * side + x) * 4;
            let [blue, green, red, alpha] = data[at..at + 4].try_into().unwrap();
            u32::from_be_bytes([alpha, red, green, blue])
        };
        let masked = |x: usize, y: usize| {
            let at = 40 + side * side * 4 + (side - 1 - y) * 4 + x / 8;
            data[at] & (0x80 >> (x % 8)) != 0
        };
        for y in 0..side {
            for x in 0..side {
                let expected = pixels[y * side + x];
                assert_eq!(pixel(x, y), expected, "({x}, {y})");
                assert_eq!(masked(x, y), expected >> 24 == 0, "({x}, {y})");
            }
        }
    }
}

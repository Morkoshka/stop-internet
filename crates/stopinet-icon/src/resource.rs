//! The icon and the version of a program as Windows resources, in a `.res`
//! file, the output format of the resource compiler. The MSVC linker takes
//! a `.res` file among its inputs, so the build needs neither the resource
//! compiler of the Windows SDK nor a crate that looks for it.
//!
//! The file holds:
//! - the images of the green shield (`RT_ICON`) and their directory
//!   (`RT_GROUP_ICON`, ID 1), the icon of the program in Explorer, in the
//!   taskbar and in Task Manager;
//! - the version (`RT_VERSION`), which the Details tab of the file
//!   properties and Task Manager read, in US English.

use std::env;
use std::fs;
use std::path::Path;

use crate::{Color, ico};

/// The values the programs share; the installer has the same ones.
const PRODUCT: &str = "stop-internet";
const PUBLISHER: &str = "Morkoshka";
/// As in `LICENSE`.
const COPYRIGHT: &str = "Copyright (c) 2026 Morkoshka";

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
const RT_VERSION: u16 = 16;

/// Memory flags as the resource compiler sets them for each type; Windows
/// ignores them.
const ICON_FLAGS: u16 = 0x1010;
const GROUP_FLAGS: u16 = 0x1030;
const VERSION_FLAGS: u16 = 0x0030;

/// English (United States), and the code page of UTF-16 in the version.
const LANGUAGE: u16 = 0x0409;
const CODE_PAGE: u16 = 1200;

/// Size of a resource header whose type and name are both numbers.
const HEADER: u32 = 32;

/// For the build script of a program: writes the icon and the version
/// into `resources.res` in `OUT_DIR` and has cargo link it into the
/// binaries of the package (not into its tests). `file_name` is the name
/// of the program file, `description` the name that Task Manager shows.
///
/// The version is the one of the package.
pub fn embed(file_name: &str, description: &str) {
    // The build script reruns when it changes, or when this crate does and
    // the script is built again.
    println!("cargo::rerun-if-changed=build.rs");
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        println!("cargo::warning=no icon and version: .res files need the MSVC linker");
        return;
    }
    let program = Program {
        file_name,
        description,
        version: Version::of_package(),
    };
    let out = env::var_os("OUT_DIR").expect("cargo sets OUT_DIR for build scripts");
    let path = Path::new(&out).join("resources.res");
    if let Err(error) = fs::write(&path, resources(&program)) {
        panic!("cannot write {}: {error}", path.display());
    }
    println!("cargo::rustc-link-arg-bins={}", path.display());
}

#[derive(Debug)]
struct Program<'a> {
    file_name: &'a str,
    description: &'a str,
    version: Version,
}

#[derive(Debug)]
struct Version {
    /// As in `Cargo.toml`, `0.1.0` or `0.2.0-beta.1`.
    text: String,
    /// Major, minor, patch and 0, as the numbers of a Windows version.
    numbers: [u16; 4],
    pre_release: bool,
}

impl Version {
    fn of_package() -> Self {
        let var = |name: &str| env::var(name).unwrap_or_else(|_| panic!("cargo sets {name}"));
        let number = |name: &str| {
            var(name)
                .parse()
                .unwrap_or_else(|_| panic!("{name} does not fit a Windows version"))
        };
        Self {
            text: var("CARGO_PKG_VERSION"),
            numbers: [
                number("CARGO_PKG_VERSION_MAJOR"),
                number("CARGO_PKG_VERSION_MINOR"),
                number("CARGO_PKG_VERSION_PATCH"),
                0,
            ],
            pre_release: !var("CARGO_PKG_VERSION_PRE").is_empty(),
        }
    }
}

/// The `.res` file: an empty resource, as every such file begins, the
/// images, the icon that groups them, and the version.
fn resources(program: &Program) -> Vec<u8> {
    let images = ico::images(Color::Green);
    let mut res = Vec::new();
    // No data; type 0 and name 0; the rest zero.
    res.extend(0u32.to_le_bytes());
    res.extend(HEADER.to_le_bytes());
    res.extend([0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0]);
    res.resize(HEADER as usize, 0);

    for (id, image) in (1..).zip(&images) {
        entry(&mut res, RT_ICON, id, ICON_FLAGS, &image.data);
    }
    entry(
        &mut res,
        RT_GROUP_ICON,
        1,
        GROUP_FLAGS,
        &ico::group(&images, 1),
    );
    entry(
        &mut res,
        RT_VERSION,
        1,
        VERSION_FLAGS,
        &version_info(program),
    );
    res
}

/// A resource whose type and name are numbers, padded to 4 bytes.
fn entry(res: &mut Vec<u8>, kind: u16, id: u16, flags: u16, data: &[u8]) {
    let size = u32::try_from(data.len()).expect("a resource is smaller than 4 GiB");
    res.extend(size.to_le_bytes());
    res.extend(HEADER.to_le_bytes());
    for word in [0xffff, kind, 0xffff, id] {
        res.extend(word.to_le_bytes());
    }
    // Data version, the flags, the language, version and characteristics.
    res.extend(0u32.to_le_bytes());
    res.extend(flags.to_le_bytes());
    res.extend(LANGUAGE.to_le_bytes());
    res.extend([0; 8]);
    res.extend(data);
    pad(res);
}

/// `VS_VERSIONINFO`: the numbers in `VS_FIXEDFILEINFO`, then the strings
/// of one language and the list of languages.
fn version_info(program: &Program) -> Vec<u8> {
    let [major, minor, patch, build] = program.version.numbers;
    let pair = |high: u16, low: u16| (u32::from(high) << 16) | u32::from(low);
    // VS_FF_PRERELEASE.
    let flags = if program.version.pre_release { 0x2 } else { 0 };
    let fixed: Vec<u8> = [
        0xfeef_04bd,
        // Version 1.0 of the structure.
        0x0001_0000,
        // File version, then product version.
        pair(major, minor),
        pair(patch, build),
        pair(major, minor),
        pair(patch, build),
        // VS_FFI_FILEFLAGSMASK and the flags.
        0x3f,
        flags,
        // VOS_NT_WINDOWS32, VFT_APP, no subtype and no date.
        0x0004_0004,
        1,
        0,
        0,
        0,
    ]
    .iter()
    .flat_map(|value: &u32| value.to_le_bytes())
    .collect();

    let version = program.version.text.as_str();
    let internal = program
        .file_name
        .strip_suffix(".exe")
        .unwrap_or(program.file_name);
    let strings = [
        ("CompanyName", PUBLISHER),
        ("FileDescription", program.description),
        ("FileVersion", version),
        ("InternalName", internal),
        ("LegalCopyright", COPYRIGHT),
        ("OriginalFilename", program.file_name),
        ("ProductName", PRODUCT),
        ("ProductVersion", version),
    ]
    .map(|(key, value)| block(key, Value::Text(value), &[]));
    let table = block(
        &format!("{LANGUAGE:04X}{CODE_PAGE:04X}"),
        Value::None,
        &strings,
    );
    let translation: Vec<u8> = [LANGUAGE, CODE_PAGE]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let languages = block("Translation", Value::Binary(&translation), &[]);
    block(
        "VS_VERSION_INFO",
        Value::Binary(&fixed),
        &[
            block("StringFileInfo", Value::None, &[table]),
            block("VarFileInfo", Value::None, &[languages]),
        ],
    )
}

#[derive(Debug, Clone, Copy)]
enum Value<'a> {
    None,
    Binary(&'a [u8]),
    Text(&'a str),
}

/// A block of the version: its length, the length of its value (in bytes
/// for binary values, in UTF-16 units with the final zero for text), the
/// type (0 binary, 1 text), the key, the value and the children, each
/// starting on a 4-byte boundary.
fn block(key: &str, value: Value, children: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0; 6];
    wide(&mut out, key);
    pad(&mut out);
    let (value_length, kind) = match value {
        Value::None => (0, 1),
        Value::Binary(bytes) => {
            out.extend(bytes);
            (bytes.len(), 0)
        }
        Value::Text(text) => (wide(&mut out, text), 1),
    };
    for child in children {
        pad(&mut out);
        out.extend(child);
    }
    let length = u16::try_from(out.len()).expect("a version block is smaller than 64 KiB");
    let value_length = u16::try_from(value_length).expect("a value is smaller than 64 KiB");
    out[..2].copy_from_slice(&length.to_le_bytes());
    out[2..4].copy_from_slice(&value_length.to_le_bytes());
    out[4..6].copy_from_slice(&u16::to_le_bytes(kind));
    out
}

/// Appends `text` in UTF-16 with a final zero; returns the number of units.
fn wide(out: &mut Vec<u8>, text: &str) -> usize {
    let mut units = 0;
    for unit in text.encode_utf16().chain([0]) {
        out.extend(unit.to_le_bytes());
        units += 1;
    }
    units
}

fn pad(out: &mut Vec<u8>) {
    out.resize(out.len().next_multiple_of(4), 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program() -> Program<'static> {
        Program {
            file_name: "stopinet-tray.exe",
            description: "stop-internet",
            version: Version {
                text: "1.2.3-beta.4".into(),
                numbers: [1, 2, 3, 0],
                pre_release: true,
            },
        }
    }

    fn u16_at(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([bytes[at], bytes[at + 1]])
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    /// The resources of a `.res` file as (type, ID, language, data).
    fn read(res: &[u8]) -> Vec<(u16, u16, u16, &[u8])> {
        let mut entries = Vec::new();
        let mut at = 0;
        while at < res.len() {
            assert_eq!(at % 4, 0);
            let (size, header) = (u32_at(res, at) as usize, u32_at(res, at + 4) as usize);
            assert_eq!(header, HEADER as usize);
            assert_eq!(u16_at(res, at + 8), 0xffff);
            assert_eq!(u16_at(res, at + 12), 0xffff);
            let data = &res[at + header..at + header + size];
            entries.push((
                u16_at(res, at + 10),
                u16_at(res, at + 14),
                u16_at(res, at + 22),
                data,
            ));
            at += (header + size).next_multiple_of(4);
        }
        assert_eq!(at, res.len());
        entries
    }

    /// A block of the version as (key, type, value, children), checking
    /// the lengths and the alignment on the way.
    fn parse(block: &[u8]) -> (String, u16, Vec<u8>, Vec<&[u8]>) {
        let length = u16_at(block, 0) as usize;
        assert_eq!(length, block.len());
        let (value_length, kind) = (u16_at(block, 2) as usize, u16_at(block, 4));
        let mut at = 6;
        let mut key = Vec::new();
        while u16_at(block, at) != 0 {
            key.push(u16_at(block, at));
            at += 2;
        }
        at = (at + 2).next_multiple_of(4);
        let value_bytes = if kind == 1 {
            value_length * 2
        } else {
            value_length
        };
        let value = block[at..at + value_bytes].to_vec();
        at += value_bytes;
        let mut children = Vec::new();
        while at.next_multiple_of(4) < length {
            at = at.next_multiple_of(4);
            let child = u16_at(block, at) as usize;
            children.push(&block[at..at + child]);
            at += child;
        }
        assert_eq!(at, length);
        (String::from_utf16(&key).unwrap(), kind, value, children)
    }

    fn text(value: &[u8]) -> String {
        let units: Vec<u16> = value
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let (last, text) = units.split_last().unwrap();
        assert_eq!(*last, 0);
        String::from_utf16(text).unwrap()
    }

    #[test]
    fn the_file_starts_empty_and_holds_the_icon_and_the_version() {
        let res = resources(&program());
        assert_eq!(
            res[..16],
            [0, 0, 0, 0, 32, 0, 0, 0, 0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0]
        );
        let entries = read(&res);
        assert!(entries[0].3.is_empty());

        let images = ico::images(Color::Green);
        let rest = &entries[1..];
        assert_eq!(rest.len(), images.len() + 2);
        for ((kind, id, language, data), (index, image)) in
            rest.iter().zip(images.iter().enumerate())
        {
            assert_eq!(
                (*kind, *id, *language),
                (RT_ICON, index as u16 + 1, LANGUAGE)
            );
            assert_eq!(*data, image.data);
        }
        let group = &rest[images.len()];
        assert_eq!((group.0, group.1), (RT_GROUP_ICON, 1));
        assert_eq!(group.3, ico::group(&images, 1));
        let version = &rest[images.len() + 1];
        assert_eq!((version.0, version.1), (RT_VERSION, 1));
        assert_eq!(version.3, version_info(&program()));
    }

    #[test]
    fn the_version_has_the_numbers_and_the_strings() {
        let info = version_info(&program());
        let (key, kind, fixed, children) = parse(&info);
        assert_eq!((key.as_str(), kind), ("VS_VERSION_INFO", 0));
        assert_eq!(fixed.len(), 52);
        let word = |index: usize| u32_at(&fixed, index * 4);
        assert_eq!(word(0), 0xfeef_04bd);
        assert_eq!((word(2), word(3)), (0x0001_0002, 0x0003_0000));
        assert_eq!((word(4), word(5)), (0x0001_0002, 0x0003_0000));
        assert_eq!(word(7), 0x2, "pre-release");
        assert_eq!((word(8), word(9)), (0x0004_0004, 1));

        assert_eq!(children.len(), 2);
        let (key, _, _, tables) = parse(children[0]);
        assert_eq!(key, "StringFileInfo");
        let (key, _, _, strings) = parse(tables[0]);
        assert_eq!(key, "040904B0");
        let strings: Vec<(String, String)> = strings
            .iter()
            .map(|string| {
                let (key, kind, value, children) = parse(string);
                assert_eq!(kind, 1);
                assert!(children.is_empty());
                (key, text(&value))
            })
            .collect();
        let get = |name: &str| {
            strings
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(get("FileDescription"), Some("stop-internet"));
        assert_eq!(get("FileVersion"), Some("1.2.3-beta.4"));
        assert_eq!(get("ProductVersion"), Some("1.2.3-beta.4"));
        assert_eq!(get("ProductName"), Some("stop-internet"));
        assert_eq!(get("OriginalFilename"), Some("stopinet-tray.exe"));
        assert_eq!(get("InternalName"), Some("stopinet-tray"));
        assert_eq!(get("CompanyName"), Some("Morkoshka"));
        assert_eq!(get("LegalCopyright"), Some("Copyright (c) 2026 Morkoshka"));

        let (key, _, _, vars) = parse(children[1]);
        assert_eq!(key, "VarFileInfo");
        let (key, kind, value, _) = parse(vars[0]);
        assert_eq!((key.as_str(), kind), ("Translation", 0));
        assert_eq!(value, [0x09, 0x04, 0xb0, 0x04]);
    }
}

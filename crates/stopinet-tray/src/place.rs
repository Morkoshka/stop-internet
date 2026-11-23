//! Where the menu opens: to the right of the cursor and wholly outside the
//! taskbar, so that the taskbar never covers part of it. Pure geometry in
//! physical pixels, so it is covered by unit tests.

/// A rectangle in screen pixels; `right` and `bottom` are exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect {
    fn contains(&self, (x, y): (i32, i32)) -> bool {
        (self.left..self.right).contains(&x) && (self.top..self.bottom).contains(&y)
    }

    fn covers(&self, other: &Rect) -> bool {
        self.left <= other.left
            && self.top <= other.top
            && self.right >= other.right
            && self.bottom >= other.bottom
    }
}

/// The screen edge the taskbar is docked to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    Left,
    Top,
    Right,
    Bottom,
}

/// Arguments for `TrackPopupMenuEx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    pub x: i32,
    pub y: i32,
    /// The right edge of the menu is at `x`; otherwise the left edge.
    pub right_aligned: bool,
    /// The bottom edge of the menu is at `y`; otherwise the top edge.
    pub bottom_aligned: bool,
    /// What the menu must not cover if Windows has to move it to fit the
    /// screen.
    pub exclude: Rect,
    /// If the menu has to move, keep it above or below `exclude` rather
    /// than beside it.
    pub vertical: bool,
}

/// `cursor`: where the user clicked. `icon`: the icon in the notification
/// area, if known. `taskbar`: the taskbar and its edge, if known.
pub fn place(cursor: (i32, i32), icon: Option<Rect>, taskbar: Option<(Rect, Edge)>) -> Placement {
    // Chosen with the keyboard: start at the icon rather than wherever the
    // mouse pointer happens to be.
    let (x, y) = match icon {
        Some(icon) if !icon.contains(cursor) => (icon.left, icon.top),
        _ => cursor,
    };
    let point = Rect {
        left: x,
        top: y,
        right: x + 1,
        bottom: y + 1,
    };

    match taskbar {
        // The icon sits on the taskbar: open next to the taskbar.
        Some((bar, edge)) if bar.covers(&icon.unwrap_or(point)) => match edge {
            Edge::Bottom => Placement {
                x,
                y: bar.top,
                right_aligned: false,
                bottom_aligned: true,
                exclude: bar,
                vertical: true,
            },
            Edge::Top => Placement {
                x,
                y: bar.bottom,
                right_aligned: false,
                bottom_aligned: false,
                exclude: bar,
                vertical: true,
            },
            Edge::Left => Placement {
                x: bar.right,
                y,
                right_aligned: false,
                bottom_aligned: false,
                exclude: bar,
                vertical: false,
            },
            Edge::Right => Placement {
                x: bar.left,
                y,
                right_aligned: true,
                bottom_aligned: false,
                exclude: bar,
                vertical: false,
            },
        },
        // The icon is in the overflow area above the taskbar, or nothing is
        // known about the taskbar: open above the icon.
        _ => {
            let icon = icon.unwrap_or(point);
            Placement {
                x,
                y: icon.top,
                right_aligned: false,
                bottom_aligned: true,
                exclude: icon,
                vertical: true,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCREEN_WIDTH: i32 = 2560;
    const SCREEN_HEIGHT: i32 = 1440;

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }

    #[test]
    fn opens_right_of_the_cursor_above_a_bottom_taskbar() {
        let bar = rect(0, 1392, SCREEN_WIDTH, SCREEN_HEIGHT);
        let icon = rect(2200, 1400, 2232, 1432);
        let placement = place((2210, 1420), Some(icon), Some((bar, Edge::Bottom)));
        assert_eq!((placement.x, placement.y), (2210, 1392));
        assert!(!placement.right_aligned && placement.bottom_aligned);
        assert_eq!(placement.exclude, bar);
        assert!(placement.vertical);
    }

    #[test]
    fn opens_below_a_top_taskbar() {
        let bar = rect(0, 0, SCREEN_WIDTH, 48);
        let icon = rect(2200, 8, 2232, 40);
        let placement = place((2210, 20), Some(icon), Some((bar, Edge::Top)));
        assert_eq!((placement.x, placement.y), (2210, 48));
        assert!(!placement.right_aligned && !placement.bottom_aligned);
    }

    #[test]
    fn opens_beside_side_taskbars() {
        let left = rect(0, 0, 64, SCREEN_HEIGHT);
        let icon = rect(16, 1200, 48, 1232);
        let placement = place((30, 1210), Some(icon), Some((left, Edge::Left)));
        assert_eq!((placement.x, placement.y), (64, 1210));
        assert!(!placement.right_aligned && !placement.vertical);

        let right = rect(SCREEN_WIDTH - 64, 0, SCREEN_WIDTH, SCREEN_HEIGHT);
        let icon = rect(SCREEN_WIDTH - 48, 1200, SCREEN_WIDTH - 16, 1232);
        let placement = place(
            (SCREEN_WIDTH - 30, 1210),
            Some(icon),
            Some((right, Edge::Right)),
        );
        assert_eq!((placement.x, placement.y), (SCREEN_WIDTH - 64, 1210));
        assert!(placement.right_aligned);
    }

    #[test]
    fn an_icon_in_the_overflow_area_opens_above_itself() {
        let bar = rect(0, 1392, SCREEN_WIDTH, SCREEN_HEIGHT);
        let icon = rect(2100, 1300, 2132, 1332);
        let placement = place((2110, 1310), Some(icon), Some((bar, Edge::Bottom)));
        assert_eq!((placement.x, placement.y), (2110, 1300));
        assert!(placement.bottom_aligned);
        assert_eq!(placement.exclude, icon);
    }

    #[test]
    fn the_keyboard_opens_at_the_icon() {
        let bar = rect(0, 1392, SCREEN_WIDTH, SCREEN_HEIGHT);
        let icon = rect(2200, 1400, 2232, 1432);
        let placement = place((500, 500), Some(icon), Some((bar, Edge::Bottom)));
        assert_eq!((placement.x, placement.y), (2200, 1392));
    }

    #[test]
    fn without_any_rectangles_it_opens_above_the_cursor() {
        let placement = place((700, 800), None, None);
        assert_eq!((placement.x, placement.y), (700, 800));
        assert!(!placement.right_aligned && placement.bottom_aligned);
    }
}

//! ASCII map view for peer locations.
//!
//! Renders a simple grid with markers:
//!   @ = own position (center)
//!   * = peer nodes
//!   . = grid background
//!
//! Pan with arrow keys. Shows distance/bearing to selected peer.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};

/// Geographic position in decimal degrees (WGS84).
#[derive(Clone, Copy, Debug, Default)]
pub struct GeoPos {
    /// Latitude in decimal degrees (-90 to +90).
    pub lat: f64,
    /// Longitude in decimal degrees (-180 to +180).
    pub lon: f64,
}

impl GeoPos {
    /// Create a new geographic position.
    pub fn new(lat: f64, lon: f64) -> Self {
        Self { lat, lon }
    }

    /// Haversine distance in meters to another position.
    pub fn distance_m(&self, other: &GeoPos) -> f64 {
        const R: f64 = 6_371_000.0; // Earth radius in meters
        let d_lat = (other.lat - self.lat).to_radians();
        let d_lon = (other.lon - self.lon).to_radians();
        let lat1 = self.lat.to_radians();
        let lat2 = other.lat.to_radians();
        let a = (d_lat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (d_lon / 2.0).sin().powi(2);
        R * 2.0 * a.sqrt().asin()
    }

    /// Bearing in degrees (0=N, 90=E, 180=S, 270=W) to another position.
    pub fn bearing_deg(&self, other: &GeoPos) -> f64 {
        let lat1 = self.lat.to_radians();
        let lat2 = other.lat.to_radians();
        let d_lon = (other.lon - self.lon).to_radians();
        let x = d_lon.cos() * lat2.cos();
        let y = lat1.cos() * lat2.sin() - lat1.sin() * x;
        let brng = d_lon.sin().atan2(y).to_degrees();
        (brng + 360.0) % 360.0
    }
}

/// A peer node with position and display metadata.
#[derive(Clone, Debug)]
pub struct MapPeer {
    /// Geographic position of the peer.
    pub pos: GeoPos,
    /// Display label (node ID or callsign).
    pub label: String,
    /// Whether this peer is currently selected for info display.
    pub selected: bool,
}

/// Map view state tracking pan offset, scale, and peer positions.
///
/// Provides an ASCII-art map centered on the user's position with
/// peers displayed as markers. Supports panning and scale adjustment.
#[derive(Debug)]
pub struct MapView {
    /// Center position (typically user's own location).
    pub center: GeoPos,
    /// List of peer nodes to display on the map.
    pub peers: Vec<MapPeer>,
    /// Pan offset in grid cells (positive = shifted right/down).
    pub pan_x: i16,
    /// Pan offset in grid cells (positive = shifted down).
    pub pan_y: i16,
    /// Meters per character cell (zoom level).
    pub scale: f64,
}

impl Default for MapView {
    fn default() -> Self {
        Self {
            center: GeoPos::default(),
            peers: Vec::new(),
            pan_x: 0,
            pan_y: 0,
            scale: 100.0, // 100m per cell
        }
    }
}

impl MapView {
    /// Adjust pan offset by the given delta (in grid cells).
    pub fn pan(&mut self, dx: i16, dy: i16) {
        self.pan_x = self.pan_x.saturating_add(dx);
        self.pan_y = self.pan_y.saturating_add(dy);
    }

    /// Reset pan offset to center the map on own position.
    pub fn reset_pan(&mut self) {
        self.pan_x = 0;
        self.pan_y = 0;
    }

    /// Returns distance (meters) and bearing (degrees) to the selected peer, if any.
    pub fn selected_info(&self) -> Option<(f64, f64)> {
        self.peers
            .iter()
            .find(|p| p.selected)
            .map(|p| (self.center.distance_m(&p.pos), self.center.bearing_deg(&p.pos)))
    }
}

/// Ratatui widget that renders the ASCII map grid.
///
/// Displays:
/// - `@` for own position (center)
/// - `*` for peer nodes
/// - Grid background with compass and scale indicators
#[derive(Debug)]
pub struct MapWidget<'a> {
    view: &'a MapView,
}

impl<'a> MapWidget<'a> {
    /// Create a new map widget from view state.
    pub fn new(view: &'a MapView) -> Self {
        Self { view }
    }

    /// Convert lat/lon to screen coordinates relative to view center.
    fn pos_to_cell(&self, pos: &GeoPos, center: &GeoPos) -> (i16, i16) {
        // Approximate meters: 1 deg lat ~= 111km, 1 deg lon ~= 111km * cos(lat)
        let lat_m = (pos.lat - center.lat) * 111_000.0;
        let lon_m = (pos.lon - center.lon) * 111_000.0 * center.lat.to_radians().cos();
        let cx = (lon_m / self.view.scale).round() as i16;
        let cy = (-lat_m / self.view.scale).round() as i16; // north = up = negative y
        (cx, cy)
    }
}

impl Widget for MapWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 3 {
            return;
        }

        // Screen center
        let scr_cx = (area.width / 2) as i16;
        let scr_cy = (area.height / 2) as i16;

        // Draw grid background (dots at intervals)
        let dot_style = Style::default().fg(Color::DarkGray);
        for y in 0..area.height {
            for x in 0..area.width {
                let ch = if (x % 5 == 0) && (y % 3 == 0) { '+' } else { '.' };
                buf[(area.x + x, area.y + y)].set_char(ch).set_style(dot_style);
            }
        }

        // Draw compass rose at top-left
        buf[(area.x + 1, area.y)].set_char('N').set_style(Style::default().fg(Color::Yellow));

        // Draw scale indicator at bottom-left
        let scale_str = format!("{}m/cell", self.view.scale as u32);
        for (i, ch) in scale_str.chars().enumerate() {
            if i < area.width as usize {
                buf[(area.x + i as u16, area.y + area.height - 1)]
                    .set_char(ch)
                    .set_style(Style::default().fg(Color::DarkGray));
            }
        }

        // Draw peers
        let peer_style = Style::default().fg(Color::Cyan);
        let sel_style = Style::default().fg(Color::Yellow);
        for peer in &self.view.peers {
            let (cx, cy) = self.pos_to_cell(&peer.pos, &self.view.center);
            let sx = scr_cx + cx + self.view.pan_x;
            let sy = scr_cy + cy + self.view.pan_y;
            if sx >= 0 && sy >= 0 && (sx as u16) < area.width && (sy as u16) < area.height {
                let style = if peer.selected { sel_style } else { peer_style };
                buf[(area.x + sx as u16, area.y + sy as u16)]
                    .set_char('*')
                    .set_style(style);
            }
        }

        // Draw own position (center marker)
        let own_x = scr_cx + self.view.pan_x;
        let own_y = scr_cy + self.view.pan_y;
        if own_x >= 0 && own_y >= 0 && (own_x as u16) < area.width && (own_y as u16) < area.height {
            buf[(area.x + own_x as u16, area.y + own_y as u16)]
                .set_char('@')
                .set_style(Style::default().fg(Color::Green));
        }
    }
}

/// Format bearing as compass direction.
pub fn bearing_to_compass(deg: f64) -> &'static str {
    match ((deg + 22.5) / 45.0) as u8 % 8 {
        0 => "N",
        1 => "NE",
        2 => "E",
        3 => "SE",
        4 => "S",
        5 => "SW",
        6 => "W",
        7 => "NW",
        _ => "?",
    }
}

/// Format distance for display.
pub fn fmt_distance(meters: f64) -> String {
    if meters < 1000.0 {
        format!("{}m", meters as u32)
    } else {
        format!("{:.1}km", meters / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_same_point() {
        let p = GeoPos::new(47.6062, -122.3321);
        assert!(p.distance_m(&p) < 0.01);
    }

    #[test]
    fn distance_known() {
        // Seattle to Portland ~= 233km
        let seattle = GeoPos::new(47.6062, -122.3321);
        let portland = GeoPos::new(45.5152, -122.6784);
        let d = seattle.distance_m(&portland);
        assert!((d - 233_000.0).abs() < 5000.0);
    }

    #[test]
    fn bearing_east() {
        let a = GeoPos::new(0.0, 0.0);
        let b = GeoPos::new(0.0, 1.0);
        let brng = a.bearing_deg(&b);
        assert!((brng - 90.0).abs() < 1.0);
    }
}

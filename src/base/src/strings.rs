// @file: strings.rs
// @author: Krisna Pranav

const STORAGE_LABELS: [char; 7] = [' ', 'K', 'M', 'G', 'T', 'P', 'E'];

pub fn bytes_to_readable_num_str(bytes_size: u64) -> String {
    let max_shift = 7;
    let mut shift = 0;
    let mut local_bytes_size = bytes_size;
    let mut value: f64 = bytes_size as f64;
    local_bytes_size >>= 10;
    while local_bytes_size > 0 && shift < max_shift {
        value /= 1024.0;
        shift += 1;
        local_bytes_size >>= 10;
    }
    format!("{0:.2}{1}", value, STORAGE_LABELS[shift])
}

pub fn units_to_readable_num_str(units: u64) -> String {
    format!("{:.6} db3", units as f64 / 1000_000_000.0)
}
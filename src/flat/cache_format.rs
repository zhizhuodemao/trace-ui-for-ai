/// Section-based binary cache format for zero-copy mmap access.
///
/// File layout:
///   [u32 num_sections]
///   [SectionEntry x N]  -- each entry: { offset: u64, length: u64 }
///   [section data, each 8-byte aligned]
///
/// All offsets are absolute (relative to the start of the section table).

pub struct SectionWriter {
    sections: Vec<(usize, usize)>, // (start_offset_in_buf, byte_length)
    buf: Vec<u8>,
}

impl SectionWriter {
    pub fn new() -> Self {
        Self {
            sections: Vec::new(),
            buf: Vec::new(),
        }
    }

    /// Write a slice of Copy types as a section. Returns section index.
    pub fn write_slice<T: Copy>(&mut self, data: &[T]) -> usize {
        // Align to 8 bytes
        while self.buf.len() % 8 != 0 {
            self.buf.push(0);
        }
        let offset = self.buf.len();
        let byte_len = data.len() * std::mem::size_of::<T>();
        let ptr = data.as_ptr() as *const u8;
        self.buf
            .extend_from_slice(unsafe { std::slice::from_raw_parts(ptr, byte_len) });
        self.sections.push((offset, byte_len));
        self.sections.len() - 1
    }

    /// Write a single u32 as a section.
    pub fn write_u32(&mut self, val: u32) -> usize {
        self.write_slice(&[val])
    }

    /// Write a single u64 as a section.
    #[allow(dead_code)]
    pub fn write_u64(&mut self, val: u64) -> usize {
        self.write_slice(&[val])
    }

    /// Write raw bytes as a section (for bincode-serialized data like CallTree).
    pub fn write_bytes(&mut self, data: &[u8]) -> usize {
        self.write_slice(data)
    }

    /// Finalize: returns the complete section table + data as bytes.
    /// The caller is responsible for prepending the 64-byte cache header.
    pub fn finish(self) -> Vec<u8> {
        let num_sections = self.sections.len() as u32;
        let raw_table_size = 4 + self.sections.len() * 16; // u32 + N * (u64 offset, u64 length)
        // Pad table to 8-byte alignment so section data stays aligned
        let table_size = (raw_table_size + 7) & !7;

        let mut result = Vec::with_capacity(table_size + self.buf.len());

        // Write section count
        result.extend_from_slice(&num_sections.to_le_bytes());

        // Write section entries (adjust offsets to account for table size)
        for &(offset, length) in &self.sections {
            let abs_offset = (offset + table_size) as u64;
            result.extend_from_slice(&abs_offset.to_le_bytes());
            result.extend_from_slice(&(length as u64).to_le_bytes());
        }

        // Pad table to 8-byte alignment
        while result.len() < table_size {
            result.push(0);
        }

        // Write section data
        result.extend(self.buf);
        result
    }
}

/// Reader for mmap'd section-based cache files.
/// `data` should point to the bytes AFTER the 64-byte cache header.
pub struct SectionReader<'a> {
    data: &'a [u8],
    sections: Vec<(u64, u64)>, // (offset, length) -- offsets relative to start of `data`
}

impl<'a> SectionReader<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let num_sections = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        let table_end = 4 + num_sections * 16;
        if data.len() < table_end {
            return None;
        }

        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let base = 4 + i * 16;
            let offset = u64::from_le_bytes(data[base..base + 8].try_into().ok()?);
            let length = u64::from_le_bytes(data[base + 8..base + 16].try_into().ok()?);
            sections.push((offset, length));
        }
        Some(Self { data, sections })
    }

    /// Get section data as a typed slice.
    pub fn slice<T: Copy>(&self, idx: usize) -> &'a [T] {
        let (offset, length) = self.sections[idx];
        let bytes = &self.data[offset as usize..(offset + length) as usize];
        unsafe {
            std::slice::from_raw_parts(
                bytes.as_ptr() as *const T,
                bytes.len() / std::mem::size_of::<T>(),
            )
        }
    }

    /// Get a single u32 from a section.
    pub fn u32_val(&self, idx: usize) -> u32 {
        self.slice::<u32>(idx)[0]
    }

    /// Get a single u64 from a section.
    #[allow(dead_code)]
    pub fn u64_val(&self, idx: usize) -> u64 {
        self.slice::<u64>(idx)[0]
    }

    /// Get section data as raw bytes (for bincode deserialization).
    pub fn bytes(&self, idx: usize) -> &'a [u8] {
        self.slice::<u8>(idx)
    }

    pub fn num_sections(&self) -> usize {
        self.sections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_u32_slice() {
        let data: Vec<u32> = vec![1, 2, 3, 42, 100];
        let mut w = SectionWriter::new();
        let idx = w.write_slice(&data);
        assert_eq!(idx, 0);
        let bytes = w.finish();

        let r = SectionReader::new(&bytes).unwrap();
        assert_eq!(r.num_sections(), 1);
        let out: &[u32] = r.slice(0);
        assert_eq!(out, &[1, 2, 3, 42, 100]);
    }

    #[test]
    fn test_roundtrip_u64_slice() {
        let data: Vec<u64> = vec![0xDEAD_BEEF, 0xCAFE_BABE];
        let mut w = SectionWriter::new();
        w.write_slice(&data);
        let bytes = w.finish();

        let r = SectionReader::new(&bytes).unwrap();
        let out: &[u64] = r.slice(0);
        assert_eq!(out, &[0xDEAD_BEEF, 0xCAFE_BABE]);
    }

    #[test]
    fn test_roundtrip_single_values() {
        let mut w = SectionWriter::new();
        w.write_u32(42);
        w.write_u64(9999);
        let bytes = w.finish();

        let r = SectionReader::new(&bytes).unwrap();
        assert_eq!(r.num_sections(), 2);
        assert_eq!(r.u32_val(0), 42);
        assert_eq!(r.u64_val(1), 9999);
    }

    #[test]
    fn test_roundtrip_bytes() {
        let data = b"hello world";
        let mut w = SectionWriter::new();
        w.write_bytes(data);
        let bytes = w.finish();

        let r = SectionReader::new(&bytes).unwrap();
        assert_eq!(r.bytes(0), b"hello world");
    }

    #[test]
    fn test_multiple_sections() {
        let mut w = SectionWriter::new();
        w.write_slice(&[1u32, 2, 3]); // 0
        w.write_slice(&[10u64, 20]);   // 1
        w.write_u32(99);               // 2
        w.write_bytes(b"test");        // 3
        let bytes = w.finish();

        let r = SectionReader::new(&bytes).unwrap();
        assert_eq!(r.num_sections(), 4);
        assert_eq!(r.slice::<u32>(0), &[1, 2, 3]);
        assert_eq!(r.slice::<u64>(1), &[10, 20]);
        assert_eq!(r.u32_val(2), 99);
        assert_eq!(r.bytes(3), b"test");
    }

    #[test]
    fn test_empty_section() {
        let empty: Vec<u32> = vec![];
        let mut w = SectionWriter::new();
        w.write_slice(&empty);
        let bytes = w.finish();

        let r = SectionReader::new(&bytes).unwrap();
        assert_eq!(r.slice::<u32>(0).len(), 0);
    }

    #[test]
    fn test_invalid_data() {
        assert!(SectionReader::new(&[]).is_none());
        assert!(SectionReader::new(&[0, 0, 0]).is_none());
        // num_sections = 1 but no table data
        assert!(SectionReader::new(&[1, 0, 0, 0]).is_none());
    }
}

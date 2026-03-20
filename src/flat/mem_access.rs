pub const MEM_RW_READ: u8 = 0;
pub const MEM_RW_WRITE: u8 = 1;

/// A single memory access record.
///
/// Layout is explicit `repr(C)` with manual padding to 24 bytes.
/// Archive type is Self — valid for same-endian (little-endian only) cache files.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FlatMemAccessRecord {
    pub insn_addr: u64, // u64 first to avoid padding
    pub data: u64,
    pub seq: u32,
    pub size: u8,
    pub rw: u8,        // 0=Read, 1=Write
    pub _pad: [u8; 2], // explicit pad to reach 24 bytes total
}


impl FlatMemAccessRecord {
    #[inline]
    pub fn is_read(&self) -> bool {
        self.rw == MEM_RW_READ
    }

    #[inline]
    pub fn is_write(&self) -> bool {
        self.rw == MEM_RW_WRITE
    }
}

pub struct FlatMemAccess {
    pub addrs: Vec<u64>,   // sorted unique addresses
    pub offsets: Vec<u32>, // CSR: records for addrs[i] = records[offsets[i]..offsets[i+1]]
    pub records: Vec<FlatMemAccessRecord>,
}

impl FlatMemAccess {
    pub fn view(&self) -> MemAccessView<'_> {
        MemAccessView {
            addrs: &self.addrs,
            offsets: &self.offsets,
            records: &self.records,
        }
    }
}

pub struct MemAccessView<'a> {
    addrs: &'a [u64],
    offsets: &'a [u32],
    records: &'a [FlatMemAccessRecord],
}

impl<'a> MemAccessView<'a> {
    pub fn from_raw(addrs: &'a [u64], offsets: &'a [u32], records: &'a [FlatMemAccessRecord]) -> Self {
        Self { addrs, offsets, records }
    }

    /// Binary search addrs, return records slice for the given address.
    pub fn query(&self, addr: u64) -> Option<&'a [FlatMemAccessRecord]> {
        let idx = self.addrs.binary_search(&addr).ok()?;
        let start = self.offsets[idx] as usize;
        let end = self.offsets[idx + 1] as usize;
        Some(&self.records[start..end])
    }

    /// Iterate all (addr, record) pairs.
    pub fn iter_all(&self) -> impl Iterator<Item = (u64, &FlatMemAccessRecord)> {
        self.addrs.iter().enumerate().flat_map(move |(i, &addr)| {
            let start = self.offsets[i] as usize;
            let end = self.offsets[i + 1] as usize;
            self.records[start..end].iter().map(move |rec| (addr, rec))
        })
    }

    #[allow(dead_code)]
    pub fn total_records(&self) -> usize {
        self.records.len()
    }

    #[allow(dead_code)]
    pub fn total_addresses(&self) -> usize {
        self.addrs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> FlatMemAccess {
        FlatMemAccess {
            addrs: vec![0x1000, 0x2000],
            offsets: vec![0, 2, 3],
            records: vec![
                FlatMemAccessRecord {
                    insn_addr: 0x100,
                    data: 0x42,
                    seq: 0,
                    size: 4,
                    rw: 1,
                    _pad: [0; 2],
                },
                FlatMemAccessRecord {
                    insn_addr: 0x104,
                    data: 0x43,
                    seq: 5,
                    size: 4,
                    rw: 0,
                    _pad: [0; 2],
                },
                FlatMemAccessRecord {
                    insn_addr: 0x200,
                    data: 0xFF,
                    seq: 10,
                    size: 1,
                    rw: 1,
                    _pad: [0; 2],
                },
            ],
        }
    }

    #[test]
    fn test_query_hit() {
        let flat = sample_data();
        let view = flat.view();
        let recs = view.query(0x1000).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].seq, 0);
        assert_eq!(recs[1].seq, 5);
    }

    #[test]
    fn test_query_miss() {
        let flat = sample_data();
        assert!(flat.view().query(0x9999).is_none());
    }

    #[test]
    fn test_iter_all() {
        let flat = sample_data();
        let view = flat.view();
        let all: Vec<_> = view.iter_all().collect();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].0, 0x1000);
        assert_eq!(all[2].0, 0x2000);
    }

    #[test]
    fn test_is_read_write() {
        let r = FlatMemAccessRecord {
            insn_addr: 0,
            data: 0,
            seq: 0,
            size: 1,
            rw: 0,
            _pad: [0; 2],
        };
        assert!(r.is_read());
        let w = FlatMemAccessRecord {
            insn_addr: 0,
            data: 0,
            seq: 0,
            size: 1,
            rw: 1,
            _pad: [0; 2],
        };
        assert!(w.is_write());
    }

    #[test]
    fn test_record_size() {
        assert_eq!(std::mem::size_of::<FlatMemAccessRecord>(), 24);
    }
}

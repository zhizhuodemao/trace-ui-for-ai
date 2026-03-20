pub const REG_COUNT: usize = 98; // = RegId::COUNT

pub struct FlatRegCheckpoints {
    pub interval: u32,
    pub count: u32,
    pub data: Vec<u64>, // flattened, each REG_COUNT u64s per snapshot
}

impl FlatRegCheckpoints {
    pub fn view(&self) -> RegCheckpointsView<'_> {
        RegCheckpointsView {
            interval: self.interval,
            count: self.count,
            data: &self.data,
        }
    }
}

pub struct RegCheckpointsView<'a> {
    pub interval: u32,
    count: u32,
    data: &'a [u64],
}

impl<'a> RegCheckpointsView<'a> {
    pub fn from_raw(interval: u32, count: u32, data: &'a [u64]) -> Self {
        Self { interval, count, data }
    }

    /// Returns (snapshot_seq, &[u64; REG_COUNT]) for the checkpoint at or before `seq`.
    pub fn nearest_before(&self, seq: u32) -> Option<(u32, &'a [u64; REG_COUNT])> {
        if self.count == 0 {
            return None;
        }
        let idx = ((seq / self.interval) as usize).min(self.count as usize - 1);
        let start = idx * REG_COUNT;
        let arr: &[u64; REG_COUNT] = self.data[start..start + REG_COUNT].try_into().ok()?;
        Some((idx as u32 * self.interval, arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_checkpoints(count: u32, interval: u32) -> FlatRegCheckpoints {
        let mut data = Vec::with_capacity(count as usize * REG_COUNT);
        for snap in 0..count {
            for reg in 0..REG_COUNT {
                data.push(snap as u64 * 1000 + reg as u64);
            }
        }
        FlatRegCheckpoints {
            interval,
            count,
            data,
        }
    }

    #[test]
    fn test_nearest_before_basic() {
        let flat = make_checkpoints(3, 100);
        let view = flat.view();

        // seq=0 → snapshot 0
        let (snap_seq, regs) = view.nearest_before(0).unwrap();
        assert_eq!(snap_seq, 0);
        assert_eq!(regs[0], 0);
        assert_eq!(regs[1], 1);

        // seq=100 → snapshot 1
        let (snap_seq, regs) = view.nearest_before(100).unwrap();
        assert_eq!(snap_seq, 100);
        assert_eq!(regs[0], 1000);

        // seq=200 → snapshot 2
        let (snap_seq, regs) = view.nearest_before(200).unwrap();
        assert_eq!(snap_seq, 200);
        assert_eq!(regs[0], 2000);

        // seq=299 → still snapshot 2 (clamped)
        let (snap_seq, _) = view.nearest_before(299).unwrap();
        assert_eq!(snap_seq, 200);

        // seq=500 → clamped to last snapshot (idx=2)
        let (snap_seq, _) = view.nearest_before(500).unwrap();
        assert_eq!(snap_seq, 200);
    }

    #[test]
    fn test_nearest_before_empty() {
        let flat = FlatRegCheckpoints {
            interval: 100,
            count: 0,
            data: vec![],
        };
        assert!(flat.view().nearest_before(0).is_none());
        assert!(flat.view().nearest_before(999).is_none());
    }

    #[test]
    fn test_reg_count_constant() {
        assert_eq!(REG_COUNT, 98);
    }
}

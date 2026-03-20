pub struct FlatDeps {
    pub chunk_start_lines: Vec<u32>,
    pub chunk_offsets_start: Vec<u32>, // where chunk i's offsets begin in all_offsets
    pub chunk_data_start: Vec<u32>,    // where chunk i's data begins in all_data
    pub all_offsets: Vec<u32>,
    pub all_data: Vec<u32>,
    pub patch_lines: Vec<u32>,   // sorted line numbers with patches
    pub patch_offsets: Vec<u32>, // CSR into patch_data
    pub patch_data: Vec<u32>,
}

impl FlatDeps {
    pub fn view(&self) -> DepsView<'_> {
        DepsView {
            chunk_start_lines: &self.chunk_start_lines,
            chunk_offsets_start: &self.chunk_offsets_start,
            chunk_data_start: &self.chunk_data_start,
            all_offsets: &self.all_offsets,
            all_data: &self.all_data,
            patch_lines: &self.patch_lines,
            patch_offsets: &self.patch_offsets,
            patch_data: &self.patch_data,
        }
    }
}

pub struct DepsView<'a> {
    chunk_start_lines: &'a [u32],
    chunk_offsets_start: &'a [u32],
    chunk_data_start: &'a [u32],
    all_offsets: &'a [u32],
    all_data: &'a [u32],
    patch_lines: &'a [u32],
    patch_offsets: &'a [u32],
    patch_data: &'a [u32],
}

impl<'a> DepsView<'a> {
    pub fn from_raw(
        chunk_start_lines: &'a [u32],
        chunk_offsets_start: &'a [u32],
        chunk_data_start: &'a [u32],
        all_offsets: &'a [u32],
        all_data: &'a [u32],
        patch_lines: &'a [u32],
        patch_offsets: &'a [u32],
        patch_data: &'a [u32],
    ) -> Self {
        Self {
            chunk_start_lines,
            chunk_offsets_start,
            chunk_data_start,
            all_offsets,
            all_data,
            patch_lines,
            patch_offsets,
            patch_data,
        }
    }

    /// Return dependency data for a given global line number.
    pub fn row(&self, global_line: usize) -> &'a [u32] {
        let line = global_line as u32;
        let chunk_idx = match self.chunk_start_lines.binary_search(&line) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let offsets_base = self.chunk_offsets_start[chunk_idx] as usize;
        let data_base = self.chunk_data_start[chunk_idx] as usize;
        let local = global_line - self.chunk_start_lines[chunk_idx] as usize;
        let start = self.all_offsets[offsets_base + local] as usize + data_base;
        let end = self.all_offsets[offsets_base + local + 1] as usize + data_base;
        &self.all_data[start..end]
    }

    /// Return patch data for a given global line number (empty slice if no patch).
    pub fn patch_row(&self, global_line: usize) -> &'a [u32] {
        let line = global_line as u32;
        match self.patch_lines.binary_search(&line) {
            Ok(idx) => {
                let start = self.patch_offsets[idx] as usize;
                let end = self.patch_offsets[idx + 1] as usize;
                &self.patch_data[start..end]
            }
            Err(_) => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a single-chunk FlatDeps covering lines [0, 1, 2].
    /// Line 0 → [10, 20], Line 1 → [30], Line 2 → []
    fn single_chunk() -> FlatDeps {
        // offsets: [0, 2, 3, 3]  (CSR, 4 entries for 3 lines)
        // data:    [10, 20, 30]
        FlatDeps {
            chunk_start_lines: vec![0],
            chunk_offsets_start: vec![0],
            chunk_data_start: vec![0],
            all_offsets: vec![0, 2, 3, 3],
            all_data: vec![10, 20, 30],
            patch_lines: vec![],
            patch_offsets: vec![],
            patch_data: vec![],
        }
    }

    #[test]
    fn test_single_chunk_rows() {
        let flat = single_chunk();
        let view = flat.view();
        assert_eq!(view.row(0), &[10u32, 20]);
        assert_eq!(view.row(1), &[30u32]);
        assert_eq!(view.row(2), &[] as &[u32]);
    }

    #[test]
    fn test_patch_row_miss() {
        let flat = single_chunk();
        let view = flat.view();
        assert_eq!(view.patch_row(0), &[] as &[u32]);
        assert_eq!(view.patch_row(1), &[] as &[u32]);
    }

    /// Two chunks: chunk 0 covers lines [0,1], chunk 1 covers lines [5,6].
    /// Patches on lines 1 and 5.
    fn multi_chunk_with_patches() -> FlatDeps {
        // Chunk 0: lines 0,1; offsets_base=0, data_base=0
        //   Line 0 → [1,2,3], Line 1 → [4]
        //   offsets: [0, 3, 4]   (3 entries for 2 lines)
        //   data:    [1,2,3,4]
        //
        // Chunk 1: lines 5,6; offsets_base=3, data_base=4
        //   Line 5 → [7,8], Line 6 → [9]
        //   offsets: [0, 2, 3]   (3 entries for 2 lines)
        //   data:    [7,8,9]
        //
        // all_offsets = [0, 3, 4,   0, 2, 3]
        // all_data    = [1,2,3,4,  7,8,9]
        //
        // Patches: line 1 → [100], line 5 → [200, 201]
        //   patch_lines   = [1, 5]
        //   patch_offsets = [0, 1, 3]
        //   patch_data    = [100, 200, 201]
        FlatDeps {
            chunk_start_lines: vec![0, 5],
            chunk_offsets_start: vec![0, 3],
            chunk_data_start: vec![0, 4],
            all_offsets: vec![0, 3, 4, 0, 2, 3],
            all_data: vec![1, 2, 3, 4, 7, 8, 9],
            patch_lines: vec![1, 5],
            patch_offsets: vec![0, 1, 3],
            patch_data: vec![100, 200, 201],
        }
    }

    #[test]
    fn test_multi_chunk_rows() {
        let flat = multi_chunk_with_patches();
        let view = flat.view();
        assert_eq!(view.row(0), &[1u32, 2, 3]);
        assert_eq!(view.row(1), &[4u32]);
        assert_eq!(view.row(5), &[7u32, 8]);
        assert_eq!(view.row(6), &[9u32]);
    }

    #[test]
    fn test_multi_chunk_patches() {
        let flat = multi_chunk_with_patches();
        let view = flat.view();
        // line 1 has patch
        assert_eq!(view.patch_row(1), &[100u32]);
        // line 5 has patch
        assert_eq!(view.patch_row(5), &[200u32, 201]);
        // line 0 has no patch
        assert_eq!(view.patch_row(0), &[] as &[u32]);
        // line 6 has no patch
        assert_eq!(view.patch_row(6), &[] as &[u32]);
    }
}

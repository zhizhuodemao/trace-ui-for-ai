use super::deps::DepsView;
use super::pair_split::PairSplitView;

pub struct ScanView<'a> {
    pub deps: DepsView<'a>,
    pub pair_split: PairSplitView<'a>,
    pub line_count: u32,
}

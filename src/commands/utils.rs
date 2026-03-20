/// 零分配 ASCII 大小写不敏感子串搜索
#[inline]
pub fn ascii_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window.iter().zip(needle).all(|(h, n)| h.to_ascii_lowercase() == *n)
    })
}

#![allow(dead_code)]

/// Extracts the JSON array starting at `s[0]` (which must be `[`), handling
/// nesting and strings. Returns `None` if the array is not closed.
pub(crate) fn extract_json_array(s: &str) -> Option<&str> {
    if !s.starts_with('[') {
        return None;
    }
    let (mut depth, mut in_string, mut escaped) = (0i32, false, false);
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            _ if in_string => {}
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Descriptions are printed on one line.
pub(crate) fn one_line(s: &str) -> String {
    s.replace('\n', "  ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_array() {
        assert_eq!(extract_json_array(r#"[1,[2],"a]\"b"],rest"#), Some(r#"[1,[2],"a]\"b"]"#));
        assert_eq!(extract_json_array("[1,2"), None);
        assert_eq!(extract_json_array("x[]"), None);
    }
}

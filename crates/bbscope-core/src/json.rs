//! Small helpers for reading loosely-typed JSON (`a.b.0.c` style paths).

use serde_json::Value;

pub trait JsonExt {
    /// Value at a dotted path (`"data.0.attributes.handle"`).
    fn at(&self, path: &str) -> Option<&Value>;

    /// String at `path`; numbers and bools are stringified, missing -> "".
    fn str_at(&self, path: &str) -> String {
        match self.at(path) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::Bool(b)) => b.to_string(),
            _ => String::new(),
        }
    }

    fn i64_at(&self, path: &str) -> i64 {
        match self.at(path) {
            Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(0),
            Some(Value::String(s)) => s.parse().unwrap_or(0),
            _ => 0,
        }
    }

    fn bool_at(&self, path: &str) -> bool {
        match self.at(path) {
            Some(Value::Bool(b)) => *b,
            Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
            Some(Value::String(s)) => s == "true" || s == "1",
            _ => false,
        }
    }

    /// Array at `path`, or an empty slice.
    fn arr_at(&self, path: &str) -> &[Value];
}

impl JsonExt for Value {
    fn at(&self, path: &str) -> Option<&Value> {
        if path.is_empty() {
            return Some(self);
        }
        path.split('.').try_fold(self, |v, key| match v {
            Value::Object(m) => m.get(key),
            Value::Array(a) => key.parse::<usize>().ok().and_then(|i| a.get(i)),
            _ => None,
        })
    }

    fn arr_at(&self, path: &str) -> &[Value] {
        match self.at(path) {
            Some(Value::Array(a)) => a.as_slice(),
            _ => &[],
        }
    }
}

/// Parses a body as JSON, returning `Value::Null` on failure.
pub fn parse(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        let v = parse(r#"{"a":{"b":[{"c":"x","n":3,"t":true}]}}"#);
        assert_eq!(v.str_at("a.b.0.c"), "x");
        assert_eq!(v.i64_at("a.b.0.n"), 3);
        assert!(v.bool_at("a.b.0.t"));
        assert_eq!(v.arr_at("a.b").len(), 1);
        assert_eq!(v.str_at("a.missing"), "");
    }
}

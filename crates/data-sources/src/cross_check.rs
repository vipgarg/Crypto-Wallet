//! Exact comparison of provider answers (§5.5). No majority voting.

use serde::Serialize;

/// The outcome of asking every provider the same question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CrossChecked<T> {
    /// Two or more providers answered and all answers are identical.
    Verified { value: T, sources: Vec<String> },
    /// Only one provider answered. Shown with a warning; never enough to act on.
    Unverified {
        value: T,
        source: String,
        failed: Vec<(String, String)>,
    },
    /// Providers gave different answers. Nothing is picked: all are shown.
    Disagreement { answers: Vec<(String, T)> },
    /// No provider answered.
    Unavailable { failed: Vec<(String, String)> },
}

impl<T> CrossChecked<T> {
    pub fn value(&self) -> Option<&T> {
        match self {
            CrossChecked::Verified { value, .. } | CrossChecked::Unverified { value, .. } => {
                Some(value)
            }
            _ => None,
        }
    }

    pub fn is_verified(&self) -> bool {
        matches!(self, CrossChecked::Verified { .. })
    }
}

/// Combine `(provider id, result)` pairs into a [`CrossChecked`].
pub fn cross_check<T, E>(results: Vec<(String, Result<T, E>)>) -> CrossChecked<T>
where
    T: PartialEq + Clone,
    E: std::fmt::Display,
{
    let mut ok: Vec<(String, T)> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    for (id, r) in results {
        match r {
            Ok(v) => ok.push((id, v)),
            Err(e) => failed.push((id, e.to_string())),
        }
    }
    match ok.len() {
        0 => CrossChecked::Unavailable { failed },
        1 => {
            let (source, value) = ok.remove(0);
            CrossChecked::Unverified {
                value,
                source,
                failed,
            }
        }
        _ => {
            let first = ok[0].1.clone();
            if ok.iter().all(|(_, v)| *v == first) {
                CrossChecked::Verified {
                    value: first,
                    sources: ok.into_iter().map(|(id, _)| id).collect(),
                }
            } else {
                CrossChecked::Disagreement { answers: ok }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(id: &str, v: Result<u64, &str>) -> (String, Result<u64, String>) {
        (id.to_owned(), v.map_err(str::to_owned))
    }

    #[test]
    fn two_equal_answers_verify() {
        let c = cross_check(vec![r("a", Ok(5)), r("b", Ok(5))]);
        assert!(c.is_verified());
        assert_eq!(c.value(), Some(&5));
    }

    #[test]
    fn any_difference_is_a_disagreement_even_with_a_majority() {
        let c = cross_check(vec![r("a", Ok(5)), r("b", Ok(5)), r("c", Ok(6))]);
        assert!(matches!(c, CrossChecked::Disagreement { .. }));
        assert_eq!(c.value(), None);
    }

    #[test]
    fn one_answer_is_unverified() {
        let c = cross_check(vec![r("a", Ok(5)), r("b", Err("timeout"))]);
        match c {
            CrossChecked::Unverified {
                value,
                source,
                failed,
            } => {
                assert_eq!((value, source.as_str()), (5, "a"));
                assert_eq!(failed, vec![("b".to_owned(), "timeout".to_owned())]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn no_answers_is_unavailable() {
        let c = cross_check::<u64, String>(vec![r("a", Err("x")), r("b", Err("y"))]);
        assert!(matches!(c, CrossChecked::Unavailable { .. }));
        let none = cross_check::<u64, String>(vec![]);
        assert!(matches!(none, CrossChecked::Unavailable { .. }));
    }
}

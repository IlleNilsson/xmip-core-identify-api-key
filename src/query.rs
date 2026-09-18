//! The query component of a request target, read for one parameter.
//!
//! RFC 3986 section 3.4: what stands between the first `?` and the `#`, as
//! `name=value` pairs separated by `&`, each percent-encoded. A `+` is left
//! as it is written: an API key is not a form field, and base64 keys carry
//! one.

use identify::IdentifyError;

/// One parameter's value from a URI's query, percent-decoded; the first where
/// the name appears twice, `None` where the URI has no query or no such name.
///
/// # Errors
///
/// Where the named parameter is there and its value holds a percent escape
/// that is not two hexadecimal digits, or decodes to something that is not
/// UTF-8.
pub fn parameter(uri: &str, name: &str) -> Result<Option<String>, IdentifyError> {
    let Some((_, query)) = uri.split_once('?') else {
        return Ok(None);
    };
    let query = query.split_once('#').map_or(query, |(query, _)| query);

    query
        .split('&')
        .find_map(|pair| {
            let (candidate, value) = pair.split_once('=').unwrap_or((pair, ""));
            (candidate == name).then_some(value)
        })
        .map(|value| decode(value, name))
        .transpose()
}

/// Percent-decode one value.
fn decode(value: &str, name: &str) -> Result<String, IdentifyError> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut rest = value.as_bytes();

    while let Some((&first, tail)) = rest.split_first() {
        if first == b'%' {
            let byte = tail
                .get(..2)
                .and_then(|pair| core::str::from_utf8(pair).ok())
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| {
                    IdentifyError::new(format!(
                        "the query parameter {name} holds a percent escape that is not two \
                         hexadecimal digits"
                    ))
                })?;
            bytes.push(byte);
            rest = &tail[2..];
        } else {
            bytes.push(first);
            rest = tail;
        }
    }

    String::from_utf8(bytes).map_err(|_| {
        IdentifyError::new(format!(
            "the query parameter {name} does not decode to UTF-8"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parameter_is_read_from_between_the_question_mark_and_the_fragment() {
        let uri = "https://xmip.example/in?format=xml&api_key=k-1%2Bz+y#api_key=other";

        assert_eq!(
            parameter(uri, "api_key").expect("read").as_deref(),
            Some("k-1+z+y")
        );
        assert_eq!(parameter(uri, "missing").expect("read"), None);
        assert_eq!(
            parameter("https://xmip.example/in", "api_key").expect("read"),
            None
        );
    }

    #[test]
    fn a_broken_percent_escape_is_an_error_only_in_the_parameter_asked_for() {
        let uri = "https://xmip.example/in?other=%zz&api_key=%4";

        let failure = parameter(uri, "api_key").expect_err("truncated escape");

        assert!(failure.message.contains("percent escape"), "{failure}");
        assert_eq!(parameter(uri, "absent").expect("read"), None);
    }
}

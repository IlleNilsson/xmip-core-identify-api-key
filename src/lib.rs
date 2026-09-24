#![forbid(unsafe_code)]

//! Identify by api-key: a key in a header or a query parameter, presented as
//! its id and never as itself.
//!
//! No standard describes an API key; the convention is universal all the
//! same. A client is issued an opaque string and sends it with every request,
//! most often in an `X-API-Key` header and sometimes as a query parameter on
//! the request target. This identifier is built naming one of the two places
//! and presents what it finds there under [`xcore::mechanism::api_key`],
//! passed.
//!
//! **The key is the secret, so the key is not the claim.** What goes on the
//! record is a name for the key:
//!
//! ```text
//! pk_7f3a.c2VjcmV0   with an id separator of '.'   value pk_7f3a
//! c2VjcmV0c2VjcmV0   with no id in it              value sha256:1f0c… (sixteen hex digits)
//! ```
//!
//! Where the issuer puts a public id in front of the secret, the identifier
//! is told the separator and the id is the value. Anywhere else the value is
//! the first eight bytes of the key's SHA-256, enough for an operator to tell
//! two keys apart and for a key store to be indexed by, and nothing a key can
//! be recovered from. The key itself rides on [`Presented::proof`] as
//! `api-key`, for `authenticate/api-key` to check against its store, and
//! reaches neither the evidence nor a log line.
//!
//! A header is read from `http.header.<name>`, the name lowercased. A query
//! parameter is read from `http.query.<name>` where the transport promoted
//! the decoded parameter, and otherwise out of the query of the arrival's
//! source URI. Only a pushed Stream carries a caller's key; on a scheduled
//! pickup any key in play was Xmip's own.
//!
//! Evidence this technology writes: `api-key.source`, `header:<name>` or
//! `query:<name>`. Proof it writes: `api-key`.

pub mod query;

use context::property::{HTTP_HEADER_PREFIX, HTTP_QUERY_PREFIX};
use identify::evidence;
use identify::{IdentifyError, Presented, StreamArrival, TransportIdentifier};
use sha2::{Digest, Sha256};
use xcore::{Arriving, Mechanism};

/// The header read where none is named.
pub const DEFAULT_HEADER: &str = "x-api-key";

/// Where the key is looked for.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Place {
    Header(String),
    Query(String),
}

/// Reads an API key from one header or one query parameter.
#[derive(Clone, Debug)]
pub struct ApiKey {
    place: Place,
    id_separator: Option<char>,
}

impl ApiKey {
    /// Read the key from this header. The name is matched without regard to
    /// case, as HTTP compares it.
    #[must_use]
    pub fn header(name: &str) -> Self {
        Self {
            place: Place::Header(name.trim().to_ascii_lowercase()),
            id_separator: None,
        }
    }

    /// Read the key from this query parameter. The name is matched exactly,
    /// as a URI compares it.
    #[must_use]
    pub fn query(name: &str) -> Self {
        Self {
            place: Place::Query(name.trim().to_string()),
            id_separator: None,
        }
    }

    /// The issuer's keys carry a public id in front of this character, and
    /// the id is the value. A key without the character is still presented
    /// by its digest.
    #[must_use]
    pub fn with_id_separator(mut self, separator: char) -> Self {
        self.id_separator = Some(separator);
        self
    }

    /// Where this reads the key from, as the evidence says it: `header:<name>`
    /// or `query:<name>`.
    #[must_use]
    pub fn source(&self) -> String {
        match &self.place {
            Place::Header(name) => format!("header:{name}"),
            Place::Query(name) => format!("query:{name}"),
        }
    }

    fn key(&self, arrival: &StreamArrival<'_>) -> Result<Option<String>, IdentifyError> {
        match &self.place {
            Place::Header(name) => Ok(arrival
                .property(&format!("{HTTP_HEADER_PREFIX}{name}"))
                .map(|value| value.trim().to_string())),
            Place::Query(name) => match arrival.property(&format!("{HTTP_QUERY_PREFIX}{name}")) {
                Some(value) => Ok(Some(value.trim().to_string())),
                None => query::parameter(arrival.source_uri(), name),
            },
        }
    }

    /// The name a key goes on the record under: its id where it carries one,
    /// else a prefix of its SHA-256.
    fn name_of(&self, key: &str) -> String {
        let id = self
            .id_separator
            .and_then(|separator| key.split_once(separator))
            .map(|(id, _)| id)
            .filter(|id| !id.is_empty());

        id.map_or_else(|| digest(key), str::to_string)
    }
}

impl Default for ApiKey {
    /// Reads the `X-API-Key` header.
    fn default() -> Self {
        Self::header(DEFAULT_HEADER)
    }
}

/// The name a key with no id goes by: the capability's
/// `identify::api_key::digest_name` of its SHA-256, which the second gate
/// finds the stored key by.
#[must_use]
pub fn digest(key: &str) -> String {
    identify::api_key::digest_name(&Sha256::digest(key.as_bytes()))
}

impl TransportIdentifier for ApiKey {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::api_key()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }

        let Some(key) = self.key(arrival)? else {
            return Ok(None);
        };

        if key.is_empty() {
            return Err(IdentifyError::new(format!(
                "the API key at {} is present and empty",
                self.source()
            )));
        }
        if key.chars().any(char::is_control) {
            return Err(IdentifyError::new(format!(
                "the API key at {} holds a control character",
                self.source()
            )));
        }

        Ok(Some(
            Presented::passed(self.mechanism(), self.name_of(&key))
                .with_evidence(evidence::API_KEY_SOURCE, self.source())
                .with_proof(evidence::API_KEY, key),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stream::Stream;
    use xcore::{Established, Layer, StreamId};

    const KEY: &str = "c2VjcmV0c2VjcmV0";

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"<order/>".to_vec(), None)
    }

    fn facts(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn a_key_in_the_header_is_presented_by_its_digest_and_carried_whole_as_proof() {
        let stream = stream();
        let facts = facts(&[("http.header.x-api-key", KEY)]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let claim = ApiKey::default()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.mechanism.name(), "api-key");
        assert_eq!(claim.established, Established::Passed);
        assert_eq!(claim.layer(), Layer::Transport);
        assert_eq!(claim.value, digest(KEY));
        assert_eq!(
            claim.value.len(),
            identify::api_key::DIGEST_PREFIX.len() + 16
        );
        assert_eq!(claim.proof(evidence::API_KEY), Some(KEY));
        assert_eq!(
            claim.evidence,
            vec![(
                evidence::API_KEY_SOURCE.to_string(),
                "header:x-api-key".to_string()
            )]
        );
    }

    #[test]
    fn the_key_reaches_neither_the_value_nor_the_evidence_nor_a_log_line() {
        let stream = stream();
        let facts = facts(&[("http.header.x-api-key", KEY)]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let claim = ApiKey::header("X-API-Key")
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert!(!claim.value.contains(KEY));
        assert!(claim.evidence.iter().all(|(_, value)| !value.contains(KEY)));
        assert!(!format!("{claim:?}").contains(KEY));
    }

    #[test]
    fn the_digest_is_the_first_eight_bytes_of_the_keys_sha_256() {
        // SHA-256("abc") = ba7816bf 8f01cfea 414140de …, FIPS 180-2 appendix B.1.
        assert_eq!(digest("abc"), "sha256:ba7816bf8f01cfea");
    }

    #[test]
    fn a_key_with_an_id_in_front_is_presented_by_the_id() {
        let stream = stream();
        let facts = facts(&[("http.header.x-api-key", "pk_7f3a.c2VjcmV0")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let claim = ApiKey::default()
            .with_id_separator('.')
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "pk_7f3a");
        assert_eq!(claim.proof(evidence::API_KEY), Some("pk_7f3a.c2VjcmV0"));
    }

    #[test]
    fn a_key_in_the_query_is_read_from_the_source_uri_and_a_promoted_one_wins() {
        let stream = stream();
        let uri = "https://xmip/in?api_key=from%2Duri";
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, uri, &[]);

        let claim = ApiKey::query("api_key")
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.proof(evidence::API_KEY), Some("from-uri"));
        assert_eq!(
            claim.evidence,
            vec![(
                evidence::API_KEY_SOURCE.to_string(),
                "query:api_key".to_string()
            )]
        );

        let facts = facts(&[("http.query.api_key", "promoted")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, uri, &facts);
        let claim = ApiKey::query("api_key")
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.proof(evidence::API_KEY), Some("promoted"));
    }

    #[test]
    fn an_arrival_without_a_key_presents_nothing() {
        let stream = stream();
        let facts = facts(&[("http.header.x-other", "value")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in?a=b", &facts);

        assert!(
            ApiKey::default()
                .identify(&arrival)
                .expect("read")
                .is_none()
        );
        assert!(
            ApiKey::query("api_key")
                .identify(&arrival)
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn a_key_that_is_present_and_empty_is_an_error_and_not_an_absence() {
        let stream = stream();
        let facts = facts(&[("http.header.x-api-key", "  ")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let failure = ApiKey::default().identify(&arrival).expect_err("empty");

        assert_eq!(
            failure.to_string(),
            "the API key at header:x-api-key is present and empty"
        );
    }

    #[test]
    fn a_scheduled_pickup_carries_no_callers_key() {
        let stream = stream();
        let facts = facts(&[("http.header.x-api-key", KEY)]);
        let arrival =
            StreamArrival::new(&stream, Arriving::Scheduled, "https://partner/out", &facts);

        assert!(
            ApiKey::default()
                .identify(&arrival)
                .expect("read")
                .is_none()
        );
    }
}

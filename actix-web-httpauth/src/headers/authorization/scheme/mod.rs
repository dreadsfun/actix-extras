use std::fmt::{Debug, Display};

use actix_web::http::header::{HeaderValue, TryIntoHeaderValue};

pub mod basic;
pub mod bearer;

use crate::headers::authorization::errors::ParseError;

/// Authentication scheme for [`Authorization`](./struct.Authorization.html)
/// header.
pub trait Scheme: TryIntoHeaderValue + Debug + Display + Clone + Send + Sync {
    /// Try to parse the authentication scheme from the `Authorization` header.
    fn parse(header: &HeaderValue) -> Result<Self, ParseError>;
}

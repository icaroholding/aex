use thiserror::Error;

#[derive(Debug, Error)]
pub enum BillingError {
    #[error("billing backend unavailable: {0}")]
    Unavailable(String),

    #[error("org {0} not recognised by billing backend")]
    UnknownOrg(String),

    #[error("stripe API error: {0}")]
    Stripe(String),

    #[error("{0}")]
    Other(String),
}

pub type BillingResult<T> = Result<T, BillingError>;

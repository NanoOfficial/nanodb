// @file: lib.rs
// @author: Krisna Pranav

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NanoError {
    #[error("invalid db address")]
    InvalidAddress,
    #[error("fail to require lock from state")]
    StateLockBusyError,
    #[error("fail to load key pair {0}")]
    LoadKeyPairError(String),
    #[error("fail to sign a message with error {0}")]
    SignError(String),
    #[error("fail to verify the request with error {0}")]
    VerifyFailed(String),
    #[error("invalid signature siwith error {0}")]
    InvalidSignature(String),
    #[error("fail to codec key with error {0}")]
    KeyCodecError(String),
    #[error("fail to apply mutation with error {0}")]
    ApplyMutationError(String),
    #[error("fail to submit mutation session with error {0}")]
    SubmitMutationError(String),
    #[error("fail to submit request with error {0}")]
    SubmitRequestError(String),
    #[error("fail to apply bill with error {0}")]
    ApplyBillError(String),
    #[error("fail to query bill with error {0}")]
    BillQueryError(String),
    #[error("fail to apply account with error {0}")]
    ApplyAccountError(String),
    #[error("fail to apply commit with error {0}")]
    ApplyCommitError(String),
    #[error("fail to apply database with error {0}")]
    ApplyDatabaseError(String),
    #[error("fail to apply document with error {0}")]
    ApplyDocumentError(String),
    #[error("fail to get commit with error {0}")]
    GetCommitError(String),
    #[error("fail to query account with error {0}")]
    GetAccountError(String),
    #[error("out of gas with error {0}")]
    OutOfGasError(String),
    #[error("fail to call bill sdk with error {0}")]
    BillSDKError(String),
    #[error("hash codec error")]
    HashCodecError,
    #[error("fail to query kv error {0}")]
    QueryKvError(String),
    #[error("fail to query, invalid session status {0}")]
    QuerySessionStatusError(String),
    #[error("fail to verify query session {0}")]
    QuerySessionVerifyError(String),
    #[error("fail to query database {0}")]
    QueryDatabaseError(String),
    #[error("database with addr {0} was not found")]
    DatabaseNotFound(String),
    #[error("collection with name {0} was not found")]
    CollectionNotFound(String),
    #[error("the address does not match the public key")]
    InvalidSigner,
    #[error("fail to generate key for {0}")]
    SignatureKeyGenError(String),
    #[error("fail to sign message for {0}")]
    SignMessageError(String),
    #[error("fail to decode document for {0}")]
    DocumentDecodeError(String),
    #[error("fail to query document {0}")]
    QueryDocumentError(String),
    #[error("invalid op entry id bytes")]
    InvalidOpEntryIdBytes,
    #[error("invalid document id bytes")]
    InvalidDocumentIdBytes,
    #[error("invalid document bytes {0}")]
    InvalidDocumentBytes(String),
    #[error("invalid collection id bytes {0}")]
    InvalidCollectionIdBytes(String),
    #[error("invalid index id bytes {0}")]
    InvalidIndexIdBytes(String),
    #[error("document not exist with target id {0}")]
    DocumentNotExist(String),
    #[error("document modified permission error")]
    DocumentModifiedPermissionError,
    #[error("fail to store event for {0}")]
    StoreEventError(String),
    #[error("fail to store faucet for {0}")]
    StoreFaucetError(String),
    #[error("invalid filter value {0}")]
    InvalidFilterValue(String),
    #[error("invalid filter op {0}")]
    InvalidFilterOp(String),
    #[error("invalid filter type {0}")]
    InvalidFilterType(String),
    #[error("index not found for filed filter {0}")]
    IndexNotFoundForFiledFilter(String),
    #[error("invalid filter json string {0}")]
    InvalidFilterJson(String),
    #[error("invalid json string {0}")]
    InvalidJson(String),
    #[error("fail to request faucet for {0}")]
    RequestFaucetError(String),
}

pub type Result<T> = std::result::Result<T, NanoError>;
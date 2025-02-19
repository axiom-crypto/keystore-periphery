use alloy_primitives::{Bytes, B256};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::types::{AuthInputs, AuthRequestStatus, SponsoredAuthInputs};

#[rpc(server, client)]
pub trait SignatureProverApi {
    #[method(name = "keystore_authenticateTransaction")]
    async fn authenticate_transaction(
        &self,
        unauthenticated_transaction: Bytes,
        auth_inputs: AuthInputs,
    ) -> RpcResult<B256>;

    #[method(name = "keystore_getAuthenticationStatus")]
    async fn get_authentication_status(
        &self,
        request_hash: B256,
    ) -> RpcResult<Option<AuthRequestStatus>>;

    #[method(name = "keystore_authenticateSponsoredTransaction")]
    async fn authenticate_sponsored_transaction(
        &self,
        unauthenticated_transaction: Bytes,
        auth_inputs: SponsoredAuthInputs,
    ) -> RpcResult<B256>;

    #[method(name = "keystore_getSponsoredAuthenticationStatus")]
    async fn get_sponsored_authentication_status(
        &self,
        request_hash: B256,
    ) -> RpcResult<Option<AuthRequestStatus>>;
}

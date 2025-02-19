use crate::{
    keystore_types::{KeystoreAccount, L2Transaction},
    parse_tx, KeystoreAccountWithData,
};
use alloy_primitives::{Bytes, B256};

use crate::{
    error::SignatureProverError, AccountAuthInputs, AuthInputs, AuthInputsDecoder, AuthRequest,
    SponsoredAuthInputs, SponsoredAuthRequest,
};

pub trait SignatureProverInputValidator: Send + Sync + 'static {
    type Error: std::error::Error;

    type ServerAuthInput;

    fn validate(&self, input: Self::ServerAuthInput) -> Result<(), Self::Error>;
}

pub struct SignatureProverValidator<I, D, V>
where
    D: AuthInputsDecoder<ServerAuthInput = I>,
    V: SignatureProverInputValidator<ServerAuthInput = I>,
{
    auth_inputs_decoder: D,
    prover_input_validator: V,
    vkey: Bytes,
    sponsor: Option<KeystoreAccountWithData>,
}

impl<I, D, V> SignatureProverValidator<I, D, V>
where
    D: AuthInputsDecoder<ServerAuthInput = I>,
    V: SignatureProverInputValidator<ServerAuthInput = I>,
{
    pub fn new(
        auth_input_decoder: D,
        prover_input_validator: V,
        vkey: Bytes,
        sponsor: Option<KeystoreAccountWithData>,
    ) -> Self {
        Self {
            auth_inputs_decoder: auth_input_decoder,
            prover_input_validator,
            vkey,
            sponsor,
        }
    }

    pub fn validate_auth_request(
        &self,
        unauthenticated_transaction: Bytes,
        auth_inputs: AuthInputs,
    ) -> Result<AuthRequest, SignatureProverError> {
        let tx = parse_tx(unauthenticated_transaction)?;
        match tx {
            L2Transaction::Deposit(_tx) => Err(SignatureProverError::UnsupportedTransactionType),
            L2Transaction::Withdraw(_tx) => Err(SignatureProverError::UnsupportedTransactionType),
            L2Transaction::Update(tx) => {
                let account = tx.user_acct().clone();
                let proof = tx.user_proof().clone();
                let msg_hash = tx.user_msg_hash();
                self.validate_update_auth_inputs(&account, &msg_hash, &proof, &auth_inputs)?;
                Ok(AuthRequest {
                    tx: L2Transaction::Update(tx),
                    auth: AccountAuthInputs::new(account, msg_hash, auth_inputs),
                })
            }
        }
    }

    pub fn validate_sponsored_auth_request(
        &self,
        unauthenticated_transaction: Bytes,
        auth_inputs: SponsoredAuthInputs,
    ) -> Result<SponsoredAuthRequest, SignatureProverError> {
        let tx = parse_tx(unauthenticated_transaction)?;

        match tx {
            L2Transaction::Deposit(_tx) => Err(SignatureProverError::UnsupportedTransactionType),
            L2Transaction::Withdraw(_tx) => Err(SignatureProverError::UnsupportedTransactionType),
            L2Transaction::Update(tx) => {
                match auth_inputs {
                    SponsoredAuthInputs::ProveSponsored {
                        user_auth_inputs,
                        sponsor_auth_inputs,
                    } => {
                        let sponsor_account = tx
                            .sponsor_acct_bytes()
                            .option()
                            .ok_or(SignatureProverError::MissingSponsorAccount)?
                            .clone();

                        let sponsor_msg_hash = tx.sponsor_msg_hash().unwrap();
                        self.validate_update_auth_inputs(
                            &sponsor_account,
                            &sponsor_msg_hash,
                            tx.sponsor_proof(),
                            &sponsor_auth_inputs,
                        )?;

                        let user_account = tx.user_acct();
                        let user_msg_hash = tx.user_msg_hash();

                        self.validate_update_auth_inputs(
                            user_account,
                            &user_msg_hash,
                            tx.user_proof(),
                            &user_auth_inputs,
                        )?;

                        let user_auth = AccountAuthInputs::new(
                            user_account.clone(),
                            user_msg_hash,
                            user_auth_inputs,
                        );
                        let sponsor_auth = AccountAuthInputs::new(
                            sponsor_account,
                            sponsor_msg_hash,
                            sponsor_auth_inputs,
                        );

                        Ok(SponsoredAuthRequest {
                            tx: L2Transaction::Update(tx),
                            sponsor_auth,
                            user_auth: Some(user_auth),
                        })
                    }
                    SponsoredAuthInputs::ProveOnlySponsored {
                        sponsor_auth_inputs,
                        ..
                    } => {
                        let sponsor_account = tx
                            .sponsor_acct_bytes()
                            .option()
                            .ok_or(SignatureProverError::MissingSponsorAccount)?
                            .clone();

                        let sponsor_msg_hash = tx.sponsor_msg_hash().unwrap();
                        self.validate_update_auth_inputs(
                            &sponsor_account,
                            &sponsor_msg_hash,
                            tx.sponsor_proof(),
                            &sponsor_auth_inputs,
                        )?;

                        let sponsor_auth = AccountAuthInputs::new(
                            sponsor_account,
                            sponsor_msg_hash,
                            sponsor_auth_inputs,
                        );

                        Ok(SponsoredAuthRequest {
                            tx: L2Transaction::Update(tx),
                            sponsor_auth,
                            user_auth: None,
                        })
                    }
                    SponsoredAuthInputs::SponsorAndProve { user_auth_inputs } => {
                        let user_account = tx.user_acct();
                        let user_msg_hash = tx.user_msg_hash();

                        self.validate_update_auth_inputs(
                            user_account,
                            &user_msg_hash,
                            tx.user_proof(),
                            &user_auth_inputs,
                        )?;

                        let user_auth = AccountAuthInputs::new(
                            user_account.clone(),
                            user_msg_hash,
                            user_auth_inputs,
                        );

                        let sponsor = self
                            .sponsor
                            .as_ref()
                            .ok_or(SignatureProverError::ServerSponsorshipNotSupported)?;

                        // add validation for sponsor auth inputs here

                        // Auto sponsorship. Could implement here the maximum fee that sponsor is willing to pay
                        let sponsor_auth = AccountAuthInputs::new(
                            sponsor.account.clone(),
                            // unwrap OK, we set the sponsor already
                            tx.sponsor_msg_hash().unwrap(),
                            AuthInputs {
                                key_data: sponsor.data.clone(),
                                auth_data: Bytes::default(),
                            },
                        );

                        Ok(SponsoredAuthRequest {
                            tx: L2Transaction::Update(tx),
                            sponsor_auth,
                            user_auth: Some(user_auth),
                        })
                    }
                }
            }
        }
    }

    pub fn validate_withdraw_auth_inputs(
        &self,
        _account: &KeystoreAccount,
        _msg_hash: &B256,
        _proof: &Bytes,
        _auth_inputs: &AuthInputs,
    ) -> Result<(), SignatureProverError> {
        Err(SignatureProverError::UnsupportedTransactionType)
    }

    pub fn validate_update_auth_inputs(
        &self,
        account: &KeystoreAccount,
        msg_hash: &B256,
        proof: &Bytes,
        auth_inputs: &AuthInputs,
    ) -> Result<(), SignatureProverError> {
        if account.vkey != self.vkey {
            return Err(SignatureProverError::UnsupportedVerificationKey);
        }

        if !proof.is_empty() {
            return Err(SignatureProverError::ProofAlreadyExists);
        }

        let auth_inputs_decoded = self
            .auth_inputs_decoder
            .decode(auth_inputs.clone(), *msg_hash)
            .map_err(|err| SignatureProverError::AuthInputsDecodeError(err.to_string()))?;

        self.prover_input_validator
            .validate(auth_inputs_decoded)
            .map_err(|err| SignatureProverError::ValidationFailed(err.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::SignatureProverError,
        keystore_types::{KeystoreAccount, UpdateTransactionBuilder},
        AuthInputs, AuthInputsDecoder, KeystoreAccountWithData, SponsoredAuthInputs,
    };

    use alloy_primitives::{keccak256, Bytes, FixedBytes, B256, U256};

    use super::{SignatureProverInputValidator, SignatureProverValidator};

    #[derive(Clone)]
    pub struct MockInput;

    struct MockInputValidator;

    impl SignatureProverInputValidator for MockInputValidator {
        type Error = SignatureProverError;
        type ServerAuthInput = MockInput;

        fn validate(&self, _input: Self::ServerAuthInput) -> Result<(), Self::Error> {
            // For testing purposes, always return Ok
            Ok(())
        }
    }

    #[derive(Clone)]
    struct MockInputDecoder;

    impl AuthInputsDecoder for MockInputDecoder {
        type Error = SignatureProverError;
        type ServerAuthInput = MockInput;

        fn decode(
            &self,
            _auth_inputs: AuthInputs,
            _msg_hash: B256,
        ) -> Result<Self::ServerAuthInput, Self::Error> {
            Ok(MockInput)
        }
    }

    impl From<MockInput> for AuthInputs {
        fn from(_input: MockInput) -> Self {
            AuthInputs {
                key_data: Bytes::default(),
                auth_data: Bytes::default(),
            }
        }
    }

    const VKEY: Bytes = Bytes::from_static(b"vkey");

    fn update_tx_builder() -> UpdateTransactionBuilder {
        let acct = KeystoreAccount::with_salt(FixedBytes::ZERO, FixedBytes::random(), VKEY);
        UpdateTransactionBuilder::sequencer_tx(U256::from(100))
            .nonce(U256::from(0))
            .new_user_data(Bytes::from_static(&[1u8; 22]))
            .new_user_vkey(Bytes::from_static(&[1u8; 22]))
            .user_acct(acct.clone())
            .user_proof(Bytes::default())
    }

    fn signature_prover_validator(
    ) -> SignatureProverValidator<MockInput, MockInputDecoder, MockInputValidator> {
        let sponsor_data = Bytes::from_static(b"sponsor_data");
        let sponsor_acct =
            KeystoreAccount::with_salt(FixedBytes::ZERO, keccak256(&sponsor_data), VKEY);
        let sponsor = KeystoreAccountWithData {
            account: sponsor_acct,
            data: sponsor_data,
        };

        SignatureProverValidator::new(MockInputDecoder, MockInputValidator, VKEY, Some(sponsor))
    }

    #[test]
    fn test_validate_auth_request_successful() {
        let validator = signature_prover_validator();

        let tx = update_tx_builder().build().unwrap();
        let auth_inputs: AuthInputs = MockInput.into();

        let res = validator.validate_auth_request(tx.into_tx_bytes(), auth_inputs);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validate_sponsored_auth_request_successful() {
        let validator = signature_prover_validator();
        let sponsor_acct = validator.sponsor.clone().unwrap().account;

        let tx = update_tx_builder()
            .sponsor_acct(Some(sponsor_acct))
            .sponsor_proof(Bytes::default())
            .build()
            .unwrap();
        let auth_inputs: SponsoredAuthInputs = SponsoredAuthInputs::ProveSponsored {
            user_auth_inputs: MockInput.into(),
            sponsor_auth_inputs: MockInput.into(),
        };

        let res = validator.validate_sponsored_auth_request(tx.into_tx_bytes(), auth_inputs);
        assert!(res.is_ok());
    }

    #[test]
    fn test_transaction_decode_failed() {
        let validator = signature_prover_validator();
        let tx = update_tx_builder().build().unwrap();
        let original_bytes = tx.into_tx_bytes();
        let tampered_bytes = original_bytes[..original_bytes.len().saturating_sub(2)].to_vec();

        let res = validator.validate_auth_request(tampered_bytes.into(), MockInput.into());
        assert!(matches!(
            res,
            Err(SignatureProverError::TransactionDecodeFailed)
        ));
    }

    #[test]
    fn test_unsupported_verification_key() {
        let validator = signature_prover_validator();

        let tx = update_tx_builder()
            .user_acct(KeystoreAccount::with_salt(
                FixedBytes::ZERO,
                FixedBytes::random(),
                Bytes::from_static(b"wrong_vkey"),
            ))
            .build()
            .unwrap();
        let auth_inputs: AuthInputs = MockInput.into();

        let res = validator.validate_auth_request(tx.into_tx_bytes(), auth_inputs);
        assert!(matches!(
            res,
            Err(SignatureProverError::UnsupportedVerificationKey)
        ));
    }

    #[test]
    fn test_proof_already_exists() {
        let validator = signature_prover_validator();

        let tx = update_tx_builder()
            .user_proof(Bytes::from_static(b"existing_proof"))
            .build()
            .unwrap();
        let auth_inputs: AuthInputs = MockInput.into();

        let res = validator.validate_auth_request(tx.into_tx_bytes(), auth_inputs);
        assert!(matches!(res, Err(SignatureProverError::ProofAlreadyExists)));
    }
}

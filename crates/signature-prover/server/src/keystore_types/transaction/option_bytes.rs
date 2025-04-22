use alloy_primitives::{bytes, Bytes, U256};
use alloy_rlp::{Decodable, Encodable};

use super::KeystoreAccount;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OptionBytes<T> {
    bytes: Bytes,
    option: Option<T>,
}

impl<T> OptionBytes<T> {
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    pub fn option(&self) -> Option<&T> {
        self.option.as_ref()
    }

    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    pub fn into_option(self) -> Option<T> {
        self.option
    }
}

impl OptionBytes<U256> {
    pub fn u256(&self) -> U256 {
        self.option.unwrap_or(U256::ZERO)
    }
}

#[derive(thiserror::Error, Debug)]
pub struct OptionBytesError(#[from] eyre::Report);

impl std::fmt::Display for OptionBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid option bytes: {}", self.0)
    }
}

impl From<Option<U256>> for OptionBytes<U256> {
    fn from(option: Option<U256>) -> Self {
        let bytes = match option {
            Some(value) => value.to_be_bytes_vec().into(),
            None => bytes!(""),
        };

        Self { bytes, option }
    }
}

impl Default for OptionBytes<U256> {
    fn default() -> Self {
        Self {
            bytes: bytes!(""),
            option: None,
        }
    }
}

impl TryFrom<Bytes> for OptionBytes<U256> {
    type Error = OptionBytesError;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        let option = if bytes == bytes!("") {
            None
        } else {
            let value = U256::try_from_be_slice(bytes.to_vec().as_slice());
            if value.is_none() {
                return Err(OptionBytesError(eyre::eyre!(
                    "failed to convert Bytes into U256"
                )));
            }
            value
        };
        Ok(Self { bytes, option })
    }
}

impl From<Option<KeystoreAccount>> for OptionBytes<KeystoreAccount> {
    fn from(option: Option<KeystoreAccount>) -> Self {
        let bytes = match &option {
            Some(value) => {
                let mut buffer = Vec::<u8>::new();
                value.encode(&mut buffer);
                buffer.into()
            }
            None => bytes!(""),
        };
        Self { bytes, option }
    }
}

impl TryFrom<Bytes> for OptionBytes<KeystoreAccount> {
    type Error = OptionBytesError;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        let option = if bytes == bytes!("") {
            None
        } else {
            let decoded = KeystoreAccount::decode(&mut bytes.to_vec().as_slice())
                .map_err(|err| OptionBytesError(err.into()))?;
            Some(decoded)
        };
        Ok(Self { bytes, option })
    }
}

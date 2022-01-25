use frost_dalek::{Participant, nizk::NizkOfSecretKey, keygen::SecretShare, IndividualSecretKey as SecretKey, precomputation::PublicCommitmentShareList, signature::{Signer, PartialThresholdSignature}, IndividualPublicKey};
use curve25519_dalek::{ristretto::{RistrettoPoint, CompressedRistretto}, scalar::Scalar};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;


pub(crate) fn scalar_bytes_from_buff(buf: Buffer) -> [u8; 32] {
    let mut sc = [0u8; 32];
    sc.copy_from_slice(&buf);
    sc
}

fn scalar_from_buff(buf: Buffer) -> Scalar {
    Scalar::from_bits(
        scalar_bytes_from_buff(buf)
    )
}

fn scalar_to_buff(scalar: Scalar) -> Buffer {
    scalar.to_bytes().to_vec().into()
}

fn ristretto_point_to_buff(point: RistrettoPoint) -> Buffer {
    point.compress().as_bytes().to_vec().into()
}

fn ristretto_point_from_buff(buf: Buffer) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(&buf).decompress()
}

#[napi(object)]
pub(crate) struct ParticipantWrapper {
    pub index: u32,
    pub commitments: Vec<Buffer>,
    pub pos_r: Buffer,
    pub pos_s: Buffer
}

#[napi(object)]
pub(crate) struct PublicKeyWrapper {
    pub index: u32,
    pub share: Buffer
}

impl From<IndividualPublicKey> for PublicKeyWrapper {
    fn from(pubk: IndividualPublicKey) -> Self {
        Self {
            index: pubk.index,
            share: ristretto_point_to_buff(pubk.share)
        }
    }
}

impl Into<Option<IndividualPublicKey>> for PublicKeyWrapper {
    fn into(self) -> Option<IndividualPublicKey> {
        Some(IndividualPublicKey {
            index: self.index,
            share: ristretto_point_from_buff(self.share)?
        })
    }
}

impl From<Participant> for ParticipantWrapper {
    fn from(participant: Participant) -> ParticipantWrapper {
        ParticipantWrapper {
            index: participant.index,
            commitments: participant.commitments
                .into_iter()
                .map(ristretto_point_to_buff)
                .collect(),
            pos_r: scalar_to_buff(participant.proof_of_secret_key.r),
            pos_s: scalar_to_buff(participant.proof_of_secret_key.s)
        }
    }
}

impl Into<Option<Participant>> for ParticipantWrapper {
    fn into(self: ParticipantWrapper) -> Option<Participant> {
        Some(Participant {
            index: self.index,
            commitments: self.commitments
                .into_iter()
                .map(ristretto_point_from_buff)
                .collect::<Option<Vec<RistrettoPoint>>>()?,
            proof_of_secret_key: NizkOfSecretKey {
                s: scalar_from_buff(self.pos_s),
                r: scalar_from_buff(self.pos_r)
            }
        })
    }
}

#[napi(object)]
pub(crate) struct SecretShareWrapper {
    pub index: u32,
    pub polynomial_evaluation: Buffer
}

impl From<SecretShare> for SecretShareWrapper {
    fn from(share: SecretShare) -> SecretShareWrapper {
        SecretShareWrapper {
            index: share.index,
            polynomial_evaluation: scalar_to_buff(share.polynomial_evaluation)
        }
    }
}

impl Into<SecretShare> for SecretShareWrapper {
    fn into(self) -> SecretShare {
        SecretShare {
            index: self.index,
            polynomial_evaluation: scalar_from_buff(self.polynomial_evaluation)
        }
    }
}

#[napi(object)]
pub(crate) struct ParticipateRes {
    pub participant: ParticipantWrapper,
    pub coefficients_handle: i64
}

#[napi(object)]
pub(crate) struct ShareRes {
    pub their_secret_shares: Vec<SecretShareWrapper>,
    pub state_handle: i64
}

#[napi(object)]
pub(crate) struct SecretKeyWrapper {
    pub index: u32,
    pub key: Buffer
}

impl From<SecretKey> for SecretKeyWrapper {
    fn from(sk: SecretKey) -> Self {
        SecretKeyWrapper {
            index: sk.index,
            key: scalar_to_buff(sk.key)
        }
    }
}

impl Into<SecretKey> for SecretKeyWrapper {
    fn into(self) -> SecretKey {
        SecretKey {
            index: self.index,
            key: scalar_from_buff(self.key)
        }
    }
}

#[napi(object)]
pub(crate) struct DeriveRes {
    pub sk: SecretKeyWrapper,
    pub pubk: PublicKeyWrapper,
    pub gk: Buffer
}

#[napi(object)]
pub struct DualRistrettoWrap {
    pub first: Buffer,
    pub second: Buffer
}

impl From<(RistrettoPoint, RistrettoPoint)> for DualRistrettoWrap {
    fn from((p1, p2): (RistrettoPoint, RistrettoPoint)) -> Self {
        Self {
            first: ristretto_point_to_buff(p1),
            second: ristretto_point_to_buff(p2)
        }
    }
}

impl Into<Option<(RistrettoPoint, RistrettoPoint)>> for DualRistrettoWrap {
    fn into(self) -> Option<(RistrettoPoint, RistrettoPoint)> {
        let first = ristretto_point_from_buff(self.first)?;
        let second = ristretto_point_from_buff(self.second)?;
        Some((first, second))
    }
}

#[napi(object)]
pub(crate) struct PubCommitmentShareListWrapper {
    pub participant_index: u32,
    pub commitment: DualRistrettoWrap
}

impl From<PublicCommitmentShareList> for PubCommitmentShareListWrapper {
    fn from(mut pubc: PublicCommitmentShareList) -> Self {
        Self {
            participant_index: pubc.participant_index,
            commitment: pubc.commitments.remove(0).into()
        }
    }
}

impl Into<Option<PublicCommitmentShareList>> for PubCommitmentShareListWrapper {
    fn into(self) -> Option<PublicCommitmentShareList> {
        let commitment: Option<(RistrettoPoint, RistrettoPoint)> = self.commitment.into();
        Some(PublicCommitmentShareList {
            participant_index: self.participant_index,
            commitments: vec![commitment?]
        })
    }
}

#[napi(object)]
pub(crate) struct GenCommitmentShareRes {
    pub public_comm_share: PubCommitmentShareListWrapper,
    pub secret_comm_share_handle: i64
}

#[napi(object)]
pub struct SignerWrapper {
    pub participant_index: u32,
    pub published_commitment_share: DualRistrettoWrap
}

impl From<Signer> for SignerWrapper {
    fn from(signer: Signer) -> Self {
        Self {
            participant_index: signer.participant_index,
            published_commitment_share: signer.published_commitment_share.into()
        }
    }
}

impl Into<Option<Signer>> for SignerWrapper {
    fn into(self) -> Option<Signer> {
        let published_commitment_share: Option<(RistrettoPoint, RistrettoPoint)> = self.published_commitment_share.into();
        Some(Signer {
            participant_index: self.participant_index,
            published_commitment_share: published_commitment_share?
        })
    }
}

#[napi(object)]
pub(crate) struct GenAggregatorRes {
    pub aggregator_handle: i64,
    pub signers: Vec<SignerWrapper>
}

#[napi(object)]
pub(crate) struct PartialThresholdSigWrapper {
    pub index: u32,
    pub z: Buffer
}

impl From<PartialThresholdSignature> for PartialThresholdSigWrapper {
    fn from(part: PartialThresholdSignature) -> Self {
        Self {
            index: part.index,
            z: scalar_to_buff(part.z)
        }
    }
}

impl Into<PartialThresholdSignature> for PartialThresholdSigWrapper {
    fn into(self) -> PartialThresholdSignature {
        PartialThresholdSignature {
            index: self.index,
            z: scalar_from_buff(self.z)
        }
    }
}

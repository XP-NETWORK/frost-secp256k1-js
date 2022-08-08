use frost_secp256k1::{Participant, nizk::NizkOfSecretKey, keygen::{SecretShare, Coefficients, RoundOne}, IndividualSecretKey as SecretKey, precomputation::{PublicCommitmentShareList, SecretCommitmentShareList}, signature::{Signer, PartialThresholdSignature, Initial}, IndividualPublicKey, DistributedKeyGeneration, SignatureAggregator};
use k256::{Scalar, elliptic_curve::{PrimeField, group::GroupEncoding}, FieldBytes, AffinePoint, CompressedPoint, ProjectivePoint};
use napi::bindgen_prelude::{Buffer, External};
use napi_derive::napi;

pub(crate) fn scalar_bytes_from_buff(buf: Buffer) -> FieldBytes {
    FieldBytes::clone_from_slice(&buf)
}

fn scalar_from_buff(buf: Buffer) -> Option<Scalar> {
    Scalar::from_repr(
        scalar_bytes_from_buff(buf)
    ).into()
}

fn scalar_to_buff(scalar: Scalar) -> Buffer {
    scalar.to_bytes().to_vec().into()
}

fn secp256k1_point_to_buff(point: AffinePoint) -> Buffer {
    point.to_bytes().to_vec().into()
}

fn secp256k1_point_from_buff(buf: Buffer) -> Option<AffinePoint> {
    AffinePoint::from_bytes(CompressedPoint::from_slice(&buf)).into()
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
            share: secp256k1_point_to_buff(pubk.share)
        }
    }
}

impl Into<Option<IndividualPublicKey>> for PublicKeyWrapper {
    fn into(self) -> Option<IndividualPublicKey> {
        Some(IndividualPublicKey {
            index: self.index,
            share: secp256k1_point_from_buff(self.share)?
        })
    }
}

impl From<Participant> for ParticipantWrapper {
    fn from(participant: Participant) -> ParticipantWrapper {
        ParticipantWrapper {
            index: participant.index,
            commitments: participant.commitments
                .into_iter()
                .map(|p| secp256k1_point_to_buff(p.into()))
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
                .map(|p| secp256k1_point_from_buff(p).map(|v| v.into()))
                .collect::<Option<Vec<ProjectivePoint>>>()?,
            proof_of_secret_key: NizkOfSecretKey {
                s: scalar_from_buff(self.pos_s)?,
                r: scalar_from_buff(self.pos_r)?
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

impl Into<Option<SecretShare>> for SecretShareWrapper {
    fn into(self) -> Option<SecretShare> {
        Some(SecretShare {
            index: self.index,
            polynomial_evaluation: scalar_from_buff(self.polynomial_evaluation)?
        })
    }
}

#[napi(object)]
pub(crate) struct ParticipateRes {
    pub participant: ParticipantWrapper,
    pub coefficients_handle: External<Coefficients>
}

#[napi(object)]
pub(crate) struct ShareRes {
    pub their_secret_shares: Vec<SecretShareWrapper>,
    pub state_handle: External<Option<DistributedKeyGeneration<RoundOne>>>
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

impl Into<Option<SecretKey>> for SecretKeyWrapper {
    fn into(self) -> Option<SecretKey> {
        Some(SecretKey {
            index: self.index,
            key: scalar_from_buff(self.key)?
        })
    }
}

#[napi(object)]
pub(crate) struct DeriveRes {
    pub sk: SecretKeyWrapper,
    pub pubk: PublicKeyWrapper,
    pub gk: Buffer
}

#[napi(object)]
pub struct DualSecp256k1Wrap {
    pub first: Buffer,
    pub second: Buffer
}

impl From<(AffinePoint, AffinePoint)> for DualSecp256k1Wrap {
    fn from((p1, p2): (AffinePoint, AffinePoint)) -> Self {
        Self {
            first: secp256k1_point_to_buff(p1),
            second: secp256k1_point_to_buff(p2)
        }
    }
}

impl Into<Option<(AffinePoint, AffinePoint)>> for DualSecp256k1Wrap {
    fn into(self) -> Option<(AffinePoint, AffinePoint)> {
        let first = secp256k1_point_from_buff(self.first)?;
        let second = secp256k1_point_from_buff(self.second)?;
        Some((first, second))
    }
}

#[napi(object)]
pub(crate) struct PubCommitmentShareListWrapper {
    pub participant_index: u32,
    pub commitment: DualSecp256k1Wrap 
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
        let commitment: Option<(AffinePoint, AffinePoint)> = self.commitment.into();
        Some(PublicCommitmentShareList {
            participant_index: self.participant_index,
            commitments: vec![commitment?]
        })
    }
}

#[napi(object)]
pub(crate) struct GenCommitmentShareRes {
    pub public_comm_share: PubCommitmentShareListWrapper,
    pub secret_comm_share_handle: External<SecretCommitmentShareList>
}

#[napi(object)]
pub struct SignerWrapper {
    pub participant_index: u32,
    pub published_commitment_share: DualSecp256k1Wrap 
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
        let published_commitment_share: Option<(AffinePoint, AffinePoint)> = self.published_commitment_share.into();
        Some(Signer {
            participant_index: self.participant_index,
            published_commitment_share: published_commitment_share?
        })
    }
}

#[napi(object)]
pub(crate) struct GenAggregatorRes {
    pub aggregator_handle: External<Option<SignatureAggregator<Initial>>>,
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

impl Into<Option<PartialThresholdSignature>> for PartialThresholdSigWrapper {
    fn into(self) -> Option<PartialThresholdSignature> {
        Some(PartialThresholdSignature {
            index: self.index,
            z: scalar_from_buff(self.z)?
        })
    }
}

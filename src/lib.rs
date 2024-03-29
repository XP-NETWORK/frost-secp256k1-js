mod wrappers;

use std::mem::size_of;

use frost_secp256k1::{Participant, Parameters, keygen::{Coefficients, RoundOne}, DistributedKeyGeneration, generate_commitment_share_lists, SignatureAggregator, GroupKey, IndividualPublicKey, compute_message_hash, precomputation::SecretCommitmentShareList, IndividualSecretKey, signature::{Initial, ThresholdSignature, PartialThresholdSignature}};
use k256::{CompressedPoint, AffinePoint};
use napi::{Result, Error, bindgen_prelude::{Buffer, External}};
use napi_derive::napi;
use rand_core::OsRng;
use wrappers::*;

#[napi]
fn participate(uuid: u32, num_sig: u32, threshold: u32) -> ParticipateRes {
    let params = Parameters { n: num_sig, t: threshold };
    let (participant, coeff) = Participant::new(&params, uuid);
    ParticipateRes {
        participant: participant.into(),
        coefficients_handle: External::new_with_size_hint(coeff, size_of::<Coefficients>())
    }
}

#[napi]
fn generate_their_shares_and_verify_participants(
    me: ParticipantWrapper,
    coefficients_handle: External<Coefficients>,
    participants: Vec<ParticipantWrapper>,
    num_sig: u32,
    threshold: u32
) -> Result<ShareRes> {
    let params = Parameters { n: num_sig, t: threshold };
    let mut participants = participants.into_iter()
        .map(|p| {
            let participant: Option<Participant> = p.into();
            let participant = participant?;

            let pubk = participant.public_key()?;
            participant.proof_of_secret_key.verify(&participant.index, &pubk).ok()?;
            Some(participant)
        }).collect::<Option<Vec<Participant>>>().ok_or_else(|| Error::from_reason("failed to verify participants!"))?;

    let me_state = DistributedKeyGeneration::<_>::new(&params, &me.index, coefficients_handle.as_ref(), &mut participants)
        .map_err(|e| Error::from_reason(
            format!("failed to generate distributed key. misbehaving participants: {:?}", e)
        ))?;

    let their_secret_shares = me_state.their_secret_shares().map_err(|_| Error::from_reason("failed to get secret shares"))?;

    Ok(ShareRes {
        their_secret_shares: their_secret_shares.into_iter()
            .map(|s| s.clone().into()).collect(),
        state_handle: External::new(Some(me_state))
    })
}

#[napi]
fn derive_pubk_and_group_key(mut state_handle: External<Option<DistributedKeyGeneration<RoundOne>>>, me: ParticipantWrapper, my_secret_shares: Vec<SecretShareWrapper>) -> Result<DeriveRes> {
    let my_secret_shares = my_secret_shares.into_iter()
        .map(|s| s.into())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::from_reason("invalid secret shares"))?;

    let my_state = state_handle.take()
        .expect("invalid state handle!")
        .to_round_two(my_secret_shares).map_err(|_| Error::from_reason("failed to move to round two"))?;

    let participant: Option<Participant> = me.into();
    let participant = participant
        .ok_or_else(|| Error::from_reason("invalid participant"))?;
    let pubk = participant.public_key()
        .ok_or_else(|| Error::from_reason("failed to get public key"))?;

    let (group_key, secret_key) = my_state.finish(&pubk)
        .map_err(|_| Error::from_reason("failed to finish key generation"))?;

    Ok(DeriveRes {
        gk: group_key.to_bytes().to_vec().into(),
        pubk: secret_key.to_public().into(),
        sk: secret_key.into()
    })
}

#[napi]
fn gen_commitment_share_lists(uuid: u32) -> GenCommitmentShareRes {
    let (pub_comm_share, secret_comm) = generate_commitment_share_lists(&mut OsRng, uuid, 1);
    GenCommitmentShareRes {
        public_comm_share: pub_comm_share.into(),
        secret_comm_share_handle: External::new_with_size_hint(secret_comm, size_of::<SecretCommitmentShareList>())
    }
}

#[napi]
fn get_aggregator_signers(
    threshold: u32,
    num_sig: u32,
    group_key: Buffer,
    context: Buffer,
    message: Buffer,
    commitments: Vec<DualSecp256k1Wrap>,
    public_keys: Vec<PublicKeyWrapper>
) -> Result<GenAggregatorRes> {
    let gk = GroupKey::from_bytes(CompressedPoint::clone_from_slice(&group_key))
        .ok_or_else(|| Error::from_reason("invalid group key"))?;

    let mut aggregator = SignatureAggregator::new(
        Parameters { n: num_sig, t: threshold },
        gk,
        context.to_vec(),
        message.to_vec()
    );

    for (commitment, pubk) in commitments.into_iter().zip(public_keys.into_iter()) {
        let commitment: Option<(AffinePoint, AffinePoint)> = commitment.into();
        let commitment = commitment.ok_or_else(|| Error::from_reason("invalid commitment provided"))?;
        let pubk: Option<IndividualPublicKey> = pubk.into();
        let pubk = pubk.ok_or_else(|| Error::from_reason("invalid public key provided"))?;
        aggregator.include_signer(pubk.index, commitment, pubk);
    }

    let signers = aggregator.get_signers().clone();
    let aggregator_handle = External::new(Some(aggregator));

    Ok(GenAggregatorRes {
        signers: signers.into_iter().map(|v| v.into()).collect(),
        aggregator_handle
    })
}

#[napi]
fn sign_partial(
    secret_key: SecretKeyWrapper,
    group_key: Buffer,
    context: Buffer,
    message: Buffer,
    mut secret_comm_share_handle: External<SecretCommitmentShareList>,
    signers: Vec<SignerWrapper>
) -> Result<PartialThresholdSigWrapper> {
    let sk: Option<IndividualSecretKey> = secret_key.into();
    let sk = sk.ok_or_else(|| Error::from_reason("invalid secret key"))?;

    let gk = GroupKey::from_bytes(CompressedPoint::clone_from_slice(&group_key))
        .ok_or_else(|| Error::from_reason("invalid group key"))?;

    let message_hash = compute_message_hash(&context, &message);

    sk.sign(
        &message_hash,
        &gk,
        secret_comm_share_handle.as_mut(),
        0,
        &signers.into_iter()
        .map(|v| v.into()).collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::from_reason("invalid signers"))?
    ).map(|sig| sig.into())
    .map_err(|e| Error::from_reason(format!("failed to sign message {}", e)))
}

#[napi]
fn aggregate_signatures(
    mut aggregator_handle: External<Option<SignatureAggregator<Initial>>>,
    signatures: Vec<PartialThresholdSigWrapper>
) -> Result<Buffer> {
    let mut aggregator = aggregator_handle.take().expect("Invalid aggregator handle!");
    for signature in signatures {
        let sig: Option<PartialThresholdSignature> = signature.into();
        let sig = sig.ok_or_else(|| Error::from_reason("invalid partial signatures"))?;
        aggregator.include_partial_signature(sig);
    }
    let aggregator = aggregator.finalize().map_err(|_| Error::from_reason("failed to finalize aggregation"))?;
    let sig = aggregator.aggregate().map_err(|_| Error::from_reason("failed to aggregate signatures"))?;

    return Ok(sig.to_bytes().to_vec().into())
}

#[napi]
fn validate_signature(
    group_key: Buffer,
    signature: Buffer,
    context: Buffer,
    message: Buffer
) -> Result<()> {
    let gk = GroupKey::from_bytes(CompressedPoint::clone_from_slice(&group_key))
        .ok_or_else(|| Error::from_reason("invalid group key"))?;

    let message_hash = compute_message_hash(&context, &message);
    let mut sig = [0u8; 65];
    sig.copy_from_slice(&signature);
    let threshold_sig = ThresholdSignature::from_bytes(sig).ok_or_else(|| Error::from_reason("invalid threshold sig"))?;

    threshold_sig.verify(&gk, &message_hash).map_err(|_| Error::from_reason("threshold signature verification failed!"))?;

    Ok(())
}

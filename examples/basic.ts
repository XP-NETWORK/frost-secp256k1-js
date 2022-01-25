import * as FROST from "..";


const alice = FROST.participate(1, 3, 2);
const bob = FROST.participate(2, 3, 2);
const carol = FROST.participate(3, 3, 2);

// WARN: coeffcientsHandle has been consumed you can't use them again
const aliceRes = FROST.generateTheirSharesAndVerifyParticipants(alice.participant, alice.coefficientsHandle, [bob.participant, carol.participant], 3, 2);
const bobRes = FROST.generateTheirSharesAndVerifyParticipants(bob.participant, bob.coefficientsHandle, [alice.participant, carol.participant], 3, 2);
const carolRes = FROST.generateTheirSharesAndVerifyParticipants(carol.participant, carol.coefficientsHandle, [alice.participant, bob.participant], 3, 2);

const aliceMySecretShares = [bobRes.theirSecretShares[0], carolRes.theirSecretShares[0]];
const bobMySecretShares = [aliceRes.theirSecretShares[0], carolRes.theirSecretShares[1]];
const carolMySecretShares = [aliceRes.theirSecretShares[1], bobRes.theirSecretShares[1]];

// WARN: stateHandle has been consumed, you can't use it again
const aliceK = FROST.derivePubkAndGroupKey(aliceRes.stateHandle, alice.participant, aliceMySecretShares);
const bobK = FROST.derivePubkAndGroupKey(bobRes.stateHandle, bob.participant, bobMySecretShares);
const carolK = FROST.derivePubkAndGroupKey(carolRes.stateHandle, carol.participant, carolMySecretShares);

console.log("group key", aliceK.gk.toString("hex"));

const context = Buffer.from("CONTEXT STRING STOLEN FROM DALEK TEST SUITE", "ascii");
const message = Buffer.from("This is a test of the tsunami alert system. This is only a test.", "ascii");

let aliceC = FROST.genCommitmentShareLists(1);
let carolC = FROST.genCommitmentShareLists(3);

let aggrRes = FROST.getAggregatorSigners(2, 3, bobK.gk, context, message,
				[aliceC.publicCommShare.commitment, carolC.publicCommShare.commitment],
				[aliceK.pubk, carolK.pubk]
);

// WARN: secretCommShareHandle has been consumed, you can't use it again
let alicePartial = FROST.signPartial(aliceK.sk, aliceK.gk, context, message, aliceC.secretCommShareHandle, aggrRes.signers);
let carolPartial = FROST.signPartial(carolK.sk, carolK.gk, context, message, carolC.secretCommShareHandle, aggrRes.signers);

let sig = FROST.aggregateSignatures(aggrRes.aggregatorHandle, [alicePartial, carolPartial]);

console.log("signature", sig.toString("hex"));
console.log("verifying signature...");
FROST.validateSignature(bobK.gk, sig, context, message);
console.log("validated!")

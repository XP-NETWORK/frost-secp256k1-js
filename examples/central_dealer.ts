import * as FROST from ".."
import readline from "readline";


(async () => {
	const read = readline.createInterface({
		input: process.stdin,
		output: process.stdout
	});

	function askInput(q: string): Promise<string> {
		return new Promise(r => read.question(q, r))
	}

	const n = await askInput("enter the number of group members: ").then(parseInt);
	const t = await askInput("enter the threshold: ").then(parseInt);
	console.log("");

	const participants = new Array<FROST.ParticipantWrapper>(n);
	const coefficientsHandles = new Array<number>(n);

	for (let i = 0; i < n; i++) {
		const newPart = FROST.participate(i+1, n, t);
		participants[i] = newPart.participant;
		coefficientsHandles[i] = newPart.coefficientsHandle;
	}

	const participantsShareHandles = new Array<number>(n);
	const participantsMyShares = Array.from(new Array(n), () => new Array<FROST.SecretShareWrapper>());

	participants.forEach((participant, i) => {
		const otherParts = [participants.slice(0, i), participants.slice(i+1)].flat();
		const theirShares = FROST.generateTheirSharesAndVerifyParticipants(
			participant,
			coefficientsHandles[i],
			otherParts,
			n,
			t
		);
		participantsShareHandles[i] = theirShares.stateHandle;
		for (let j = n-1; j >= 0; j--) {
			if (j == i) {
				continue
			};
			participantsMyShares[j].push(theirShares.theirSecretShares.pop()!);
		}
	})

	const pubKeys = new Array<FROST.PublicKeyWrapper>(n);
	const sKeys = new Array<FROST.SecretKeyWrapper>(n);
	let groupKey: Buffer | undefined;
	participantsShareHandles.forEach((stateHandle, i) => {
		const keyRes = FROST.derivePubkAndGroupKey(
			stateHandle, participants[i], participantsMyShares[i]
		);
		console.log(`UUID: ${keyRes.pubk.index}
Public Key: ${keyRes.pubk.share.toString("hex")}
Secret Key: ${keyRes.sk.key.toString("hex")}\n`
		);
		pubKeys[i] = keyRes.pubk;
		sKeys[i] = keyRes.sk;
		groupKey = keyRes.gk;
	});

	console.log("Group Public Key:", groupKey!.toString("hex"), "\n");

	// Test signature signing
	console.log("Testing signature signing...")
	const context = Buffer.from("CONTEXT STRING", "ascii");
	const message = Buffer.from("this a test", "ascii");
	const pubComms = new Array<FROST.DualSecp256K1Wrap>();
	const secretCommHandles = new Array<number>();
	const pubKSliced = new Array<FROST.PublicKeyWrapper>(t);

	for (let i = 0; i < t; i++) {
		const comm = FROST.genCommitmentShareLists(pubKeys[i].index);
		pubComms[i] = comm.publicCommShare.commitment;
		secretCommHandles[i] = comm.secretCommShareHandle;
		pubKSliced[i] = pubKeys[i];
	}

	const aggrRes = FROST.getAggregatorSigners(
		t, n,
		groupKey!,
		context,
		message,
		pubComms,
		pubKSliced
	);

	const partialSigs = new Array<FROST.PartialThresholdSigWrapper>(t);
	for (let i = 0; i < t; i++) {
		partialSigs[i] = FROST.signPartial(
			sKeys[i],
			groupKey!,
			context,
			message,
			secretCommHandles[i],
			aggrRes.signers
		);
	}

	const signature = FROST.aggregateSignatures(aggrRes.aggregatorHandle, partialSigs);

	console.log("signature", signature.toString("hex"));
	console.log("verifying signature...");
	try {
		FROST.validateSignature(groupKey!, signature, context, message);
		console.log("validated signature!");
	} catch (e) {
		console.log("failed to validate signature, err:", e);
	}

})().then(() => process.exit(0))

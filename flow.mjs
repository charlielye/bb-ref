// One chonk flow through any service with bb's generated API (bb-ref.js's BbService or bb's
// bb.js-api BbService): the same command sequence bb.js's AztecClientBackend sends. Shared by the
// node runner and the web page, so both measure the same thing.

/** gunzip with the platform's DecompressionStream (node 18+ and every current browser). */
export async function gunzip(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** The steps of an `ivc-inputs.msgpack` (bb's pinned flow format), bytecode and witness gunzipped. */
export async function decodeIvcInputs(unpack, bytes) {
  const raw = unpack(bytes);
  return Promise.all(
    raw.map(async s => ({
      name: s.functionName,
      kind: s.kind,
      bytecode: await gunzip(s.bytecode),
      witness: await gunzip(s.witness),
      vk: new Uint8Array(s.vk),
    })),
  );
}

/** Push the CRS: BN254 points (64 bytes each, uncompressed), the G2 point, and Grumpkin chunks. */
export async function initSrs(api, { g1, g2, grumpkin }) {
  await api.srsInitSrs({ pointsBuf: g1, numPoints: g1.length / 64, g2Point: g2 });
  await api.srsInitGrumpkinSrs({ pointsBuf: grumpkin, numPoints: grumpkin.length / 64 });
}

/** Prove one flow; returns per-step load/accumulate times, the prove time and the proof bytes. */
export async function proveFlow(api, steps, onStep = () => {}) {
  const now = () => performance.now();
  const t0 = now();
  await api.chonkStart({ kinds: new Uint8Array(steps.map(s => s.kind)) });
  const perStep = [];
  for (const s of steps) {
    const a = now();
    await api.chonkLoad({ circuit: { name: s.name, bytecode: s.bytecode, verificationKey: s.vk }, kind: s.kind });
    const b = now();
    await api.chonkAccumulate({ witness: s.witness });
    const c = now();
    perStep.push({ name: s.name, load: b - a, accumulate: c - b });
    onStep(perStep.length, steps.length);
  }
  const p = now();
  const { proof } = await api.chonkProve({});
  const end = now();
  const verified = (await api.chonkVerify({ proof, vk: steps[steps.length - 1].vk })).valid;
  const fields = [proof.hidingOinkProof, proof.mergeProof, proof.eccvmProof, proof.ipaProof, proof.jointProof].flat();
  const proofBytes = new Uint8Array(fields.length * 32);
  fields.forEach((f, i) => proofBytes.set(f, i * 32));
  return {
    accumulate: p - t0,
    prove: end - p,
    total: end - t0,
    perStep,
    verified,
    proofBytes,
  };
}

export async function sha256Hex(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return [...d].map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Schema version hash for compatibility checking */
export declare const SCHEMA_HASH = "a12dd1699334c9ea9476b3338318fa81fa4506a6dd7512e50ae14e182d71eea1";
export type Fq = Uint8Array;
export type Fr = Uint8Array;
export type Secp256k1Fq = Uint8Array;
export type Secp256k1Fr = Uint8Array;
export type Secp256r1Fq = Uint8Array;
export type Secp256r1Fr = Uint8Array;
export type Uint256 = Uint8Array;
export interface AvmStat {
    name: string;
    valueMs: number;
}
export interface VkData {
    bytes: Uint8Array;
    fields: Uint256[];
    hash: Uint8Array;
}
export interface ChonkProof {
    hidingOinkProof: Fr[];
    mergeProof: Fr[];
    eccvmProof: Fr[];
    ipaProof: Fr[];
    jointProof: Fr[];
}
export interface GrumpkinPoint {
    x: Fr;
    y: Fr;
}
export interface Secp256k1Point {
    x: Secp256k1Fq;
    y: Secp256k1Fq;
}
export interface Bn254G1Point {
    x: Fq;
    y: Fq;
}
export interface Bn254G2Point {
    x: [Fq, Fq];
    y: [Fq, Fq];
}
export interface Secp256r1Point {
    x: Secp256r1Fq;
    y: Secp256r1Fq;
}
export interface AvmProve {
    inputs: Uint8Array;
}
export interface AvmVerify {
    proof: Fr[];
    publicInputs: Uint8Array;
}
export interface AvmCheckCircuit {
    inputs: Uint8Array;
}
export interface CircuitInput {
    name: string;
    bytecode: Uint8Array;
    verificationKey: Uint8Array;
}
export interface ProofSystemSettings {
    ipaAccumulation: boolean;
    oracleHashType: string;
    disableZk: boolean;
    optimizedSolidityVerifier: boolean;
}
export interface CircuitProve {
    circuit: CircuitInput;
    witness: Uint8Array;
    settings: ProofSystemSettings;
}
export interface CircuitInputNoVK {
    name: string;
    bytecode: Uint8Array;
}
export interface CircuitComputeVk {
    circuit: CircuitInputNoVK;
    settings: ProofSystemSettings;
}
export interface CircuitStats {
    circuit: CircuitInput;
    includeGatesPerOpcode: boolean;
    settings: ProofSystemSettings;
}
export interface CircuitVerify {
    verificationKey: Uint8Array;
    publicInputs: Uint256[];
    proof: Uint256[];
    settings: ProofSystemSettings;
}
export interface ChonkComputeVk {
    circuit: CircuitInputNoVK;
    kind: number;
}
export interface ChonkStart {
    kinds: Uint8Array;
}
export interface ChonkLoad {
    circuit: CircuitInput;
    kind: number;
}
export interface ChonkAccumulate {
    witness: Uint8Array;
}
export interface ChonkProve {
}
export interface ChonkVerify {
    proof: ChonkProof;
    vk: Uint8Array;
}
export interface ChonkVerifyFromFields {
    proof: Fr[];
    vk: Uint8Array;
}
export interface ChonkBatchVerify {
    proofs: ChonkProof[];
    vks: Uint8Array[];
}
export interface VkAsFields {
    verificationKey: Uint8Array;
}
export interface MegaVkAsFields {
    verificationKey: Uint8Array;
}
export interface MegaAppVkAsFields {
    verificationKey: Uint8Array;
}
export interface MegaKernelVkAsFields {
    verificationKey: Uint8Array;
}
export interface MegaZKVkAsFields {
    verificationKey: Uint8Array;
}
export interface CircuitWriteSolidityVerifier {
    verificationKey: Uint8Array;
    settings: ProofSystemSettings;
}
export interface ChonkCheckPrecomputedVk {
    circuit: CircuitInput;
    kind: number;
}
export interface ChonkStats {
    circuit: CircuitInputNoVK;
    includeGatesPerOpcode: boolean;
}
export interface ChonkCompressProof {
    proof: ChonkProof;
}
export interface ChonkDecompressProof {
    compressedProof: Uint8Array;
}
export interface Poseidon2Hash {
    inputs: Fr[];
}
export interface Poseidon2Permutation {
    inputs: Fr[];
}
export interface Poseidon2AbsorbChain {
    state: Fr[];
    inputs: Uint8Array;
}
export interface PedersenCommit {
    inputs: Fr[];
    hashIndex: number;
}
export interface PedersenHash {
    inputs: Fr[];
    hashIndex: number;
}
export interface Blake2s {
    data: Uint8Array;
}
export interface Blake2sToField {
    data: Uint8Array;
}
export interface AesEncrypt {
    plaintext: Uint8Array;
    iv: Uint8Array;
    key: Uint8Array;
    length: number;
}
export interface AesDecrypt {
    ciphertext: Uint8Array;
    iv: Uint8Array;
    key: Uint8Array;
    length: number;
}
export interface GrumpkinMul {
    point: GrumpkinPoint;
    scalar: Fq;
}
export interface GrumpkinAdd {
    pointA: GrumpkinPoint;
    pointB: GrumpkinPoint;
}
export interface GrumpkinBatchMul {
    points: GrumpkinPoint[];
    scalar: Fq;
}
export interface GrumpkinGetRandomFr {
    dummy: number;
}
export interface GrumpkinReduce512 {
    input: Uint8Array;
}
export interface Secp256k1Mul {
    point: Secp256k1Point;
    scalar: Secp256k1Fr;
}
export interface Secp256k1GetRandomFr {
    dummy: number;
}
export interface Secp256k1Reduce512 {
    input: Uint8Array;
}
export interface Bn254FrSqrt {
    input: Fr;
}
export interface Bn254FqSqrt {
    input: Fq;
}
export interface Bn254G1Mul {
    point: Bn254G1Point;
    scalar: Fr;
}
export interface Bn254G2Mul {
    point: Bn254G2Point;
    scalar: Fr;
}
export interface Bn254G1IsOnCurve {
    point: Bn254G1Point;
}
export interface Bn254G1FromCompressed {
    compressed: Uint8Array;
}
export interface SchnorrComputePublicKey {
    privateKey: Fq;
}
export interface SchnorrConstructSignature {
    messageField: Fr;
    privateKey: Fq;
}
export interface SchnorrVerifySignature {
    messageField: Fr;
    publicKey: GrumpkinPoint;
    s: Fq;
    e: Fq;
}
export interface EcdsaSecp256k1ComputePublicKey {
    privateKey: Secp256k1Fr;
}
export interface EcdsaSecp256r1ComputePublicKey {
    privateKey: Secp256r1Fr;
}
export interface EcdsaSecp256k1ConstructSignature {
    message: Uint8Array;
    privateKey: Secp256k1Fr;
}
export interface EcdsaSecp256r1ConstructSignature {
    message: Uint8Array;
    privateKey: Secp256r1Fr;
}
export interface EcdsaSecp256k1RecoverPublicKey {
    message: Uint8Array;
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
export interface EcdsaSecp256r1RecoverPublicKey {
    message: Uint8Array;
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
export interface EcdsaSecp256k1VerifySignature {
    message: Uint8Array;
    publicKey: Secp256k1Point;
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
export interface EcdsaSecp256r1VerifySignature {
    message: Uint8Array;
    publicKey: Secp256r1Point;
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
export interface SrsInitSrs {
    pointsBuf: Uint8Array;
    numPoints: number;
    g2Point: Uint8Array;
}
export interface ChonkBatchVerifierStart {
    vks: Uint8Array[];
    numCores: number;
    batchSize: number;
    fifoPath: string;
}
export interface ChonkBatchVerifierQueue {
    requestId: number;
    vkIndex: number;
    proofFields: Fr[];
}
export interface ChonkBatchVerifierStop {
}
export interface SrsInitGrumpkinSrs {
    pointsBuf: Uint8Array;
    numPoints: number;
}
export interface Init {
    warmup: boolean | null;
}
export interface AvmProveResponse {
    proof: Fr[];
    stats: AvmStat[];
}
export interface AvmVerifyResponse {
    verified: boolean;
}
export interface AvmCheckCircuitResponse {
    passed: boolean;
    stats: AvmStat[];
}
export interface CircuitProveResponse {
    publicInputs: Uint256[];
    proof: Uint256[];
    vk: VkData;
}
export interface CircuitComputeVkResponse {
    bytes: Uint8Array;
    fields: Uint256[];
    hash: Uint8Array;
}
export interface CircuitStatsResponse {
    numGates: number;
    numGatesDyadic: number;
    numAcirOpcodes: number;
    gatesPerOpcode: number[];
}
export interface CircuitVerifyResponse {
    verified: boolean;
}
export interface ChonkComputeVkResponse {
    bytes: Uint8Array;
    fields: Fr[];
}
export interface ChonkStartResponse {
}
export interface ChonkLoadResponse {
}
export interface ChonkAccumulateResponse {
}
export interface ChonkProveResponse {
    proof: ChonkProof;
}
export interface ChonkVerifyResponse {
    valid: boolean;
}
export interface ChonkVerifyFromFieldsResponse {
    valid: boolean;
}
export interface ChonkBatchVerifyResponse {
    valid: boolean;
}
export interface VkAsFieldsResponse {
    fields: Fr[];
}
export interface MegaVkAsFieldsResponse {
    fields: Fr[];
}
export interface MegaAppVkAsFieldsResponse {
    fields: Fr[];
}
export interface MegaKernelVkAsFieldsResponse {
    fields: Fr[];
}
export interface MegaZKVkAsFieldsResponse {
    fields: Fr[];
}
export interface CircuitWriteSolidityVerifierResponse {
    solidityCode: string;
}
export interface ChonkCheckPrecomputedVkResponse {
    valid: boolean;
    actualVk: Uint8Array;
}
export interface ChonkStatsResponse {
    acirOpcodes: number;
    circuitSize: number;
    gatesPerOpcode: number[];
}
export interface ChonkCompressProofResponse {
    compressedProof: Uint8Array;
}
export interface ChonkDecompressProofResponse {
    proof: ChonkProof;
}
export interface Poseidon2HashResponse {
    hash: Fr;
}
export interface Poseidon2PermutationResponse {
    outputs: Fr[];
}
export interface Poseidon2AbsorbChainResponse {
    state: Fr[];
}
export interface PedersenCommitResponse {
    point: GrumpkinPoint;
}
export interface PedersenHashResponse {
    hash: Fr;
}
export interface Blake2sResponse {
    hash: Uint8Array;
}
export interface Blake2sToFieldResponse {
    field: Fr;
}
export interface AesEncryptResponse {
    ciphertext: Uint8Array;
}
export interface AesDecryptResponse {
    plaintext: Uint8Array;
}
export interface GrumpkinMulResponse {
    point: GrumpkinPoint;
}
export interface GrumpkinAddResponse {
    point: GrumpkinPoint;
}
export interface GrumpkinBatchMulResponse {
    points: GrumpkinPoint[];
}
export interface GrumpkinGetRandomFrResponse {
    value: Fr;
}
export interface GrumpkinReduce512Response {
    value: Fr;
}
export interface Secp256k1MulResponse {
    point: Secp256k1Point;
}
export interface Secp256k1GetRandomFrResponse {
    value: Secp256k1Fr;
}
export interface Secp256k1Reduce512Response {
    value: Secp256k1Fr;
}
export interface Bn254FrSqrtResponse {
    isSquareRoot: boolean;
    value: Fr;
}
export interface Bn254FqSqrtResponse {
    isSquareRoot: boolean;
    value: Fq;
}
export interface Bn254G1MulResponse {
    point: Bn254G1Point;
}
export interface Bn254G2MulResponse {
    point: Bn254G2Point;
}
export interface Bn254G1IsOnCurveResponse {
    isOnCurve: boolean;
}
export interface Bn254G1FromCompressedResponse {
    point: Bn254G1Point;
}
export interface SchnorrComputePublicKeyResponse {
    publicKey: GrumpkinPoint;
}
export interface SchnorrConstructSignatureResponse {
    s: Fq;
    e: Fq;
}
export interface SchnorrVerifySignatureResponse {
    verified: boolean;
}
export interface EcdsaSecp256k1ComputePublicKeyResponse {
    publicKey: Secp256k1Point;
}
export interface EcdsaSecp256r1ComputePublicKeyResponse {
    publicKey: Secp256r1Point;
}
export interface EcdsaSecp256k1ConstructSignatureResponse {
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
export interface EcdsaSecp256r1ConstructSignatureResponse {
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
export interface EcdsaSecp256k1RecoverPublicKeyResponse {
    publicKey: Secp256k1Point;
}
export interface EcdsaSecp256r1RecoverPublicKeyResponse {
    publicKey: Secp256r1Point;
}
export interface EcdsaSecp256k1VerifySignatureResponse {
    verified: boolean;
}
export interface EcdsaSecp256r1VerifySignatureResponse {
    verified: boolean;
}
export interface SrsInitSrsResponse {
    pointsBuf: Uint8Array;
}
export interface ChonkBatchVerifierStartResponse {
}
export interface ChonkBatchVerifierQueueResponse {
}
export interface ChonkBatchVerifierStopResponse {
}
export interface SrsInitGrumpkinSrsResponse {
    dummy: number;
}
export interface InitResponse {
}
export interface ErrorResponse {
    message: string;
}
interface MsgpackAvmStat {
    name: string;
    value_ms: number | bigint;
}
interface MsgpackVkData {
    bytes: Uint8Array;
    fields: Uint8Array[];
    hash: Uint8Array;
}
interface MsgpackChonkProof {
    hiding_oink_proof: Uint8Array[];
    merge_proof: Uint8Array[];
    eccvm_proof: Uint8Array[];
    ipa_proof: Uint8Array[];
    joint_proof: Uint8Array[];
}
interface MsgpackGrumpkinPoint {
    x: Uint8Array;
    y: Uint8Array;
}
interface MsgpackSecp256k1Point {
    x: Uint8Array;
    y: Uint8Array;
}
interface MsgpackBn254G1Point {
    x: Uint8Array;
    y: Uint8Array;
}
interface MsgpackBn254G2Point {
    x: [Uint8Array, Uint8Array];
    y: [Uint8Array, Uint8Array];
}
interface MsgpackSecp256r1Point {
    x: Uint8Array;
    y: Uint8Array;
}
interface MsgpackAvmProve {
    inputs: Uint8Array;
}
interface MsgpackAvmVerify {
    proof: Uint8Array[];
    public_inputs: Uint8Array;
}
interface MsgpackAvmCheckCircuit {
    inputs: Uint8Array;
}
interface MsgpackCircuitInput {
    name: string;
    bytecode: Uint8Array;
    verification_key: Uint8Array;
}
interface MsgpackProofSystemSettings {
    ipa_accumulation: boolean;
    oracle_hash_type: string;
    disable_zk: boolean;
    optimized_solidity_verifier: boolean;
}
interface MsgpackCircuitProve {
    circuit: MsgpackCircuitInput;
    witness: Uint8Array;
    settings: MsgpackProofSystemSettings;
}
interface MsgpackCircuitInputNoVK {
    name: string;
    bytecode: Uint8Array;
}
interface MsgpackCircuitComputeVk {
    circuit: MsgpackCircuitInputNoVK;
    settings: MsgpackProofSystemSettings;
}
interface MsgpackCircuitStats {
    circuit: MsgpackCircuitInput;
    include_gates_per_opcode: boolean;
    settings: MsgpackProofSystemSettings;
}
interface MsgpackCircuitVerify {
    verification_key: Uint8Array;
    public_inputs: Uint8Array[];
    proof: Uint8Array[];
    settings: MsgpackProofSystemSettings;
}
interface MsgpackChonkComputeVk {
    circuit: MsgpackCircuitInputNoVK;
    kind: number;
}
interface MsgpackChonkStart {
    kinds: Uint8Array;
}
interface MsgpackChonkLoad {
    circuit: MsgpackCircuitInput;
    kind: number;
}
interface MsgpackChonkAccumulate {
    witness: Uint8Array;
}
interface MsgpackChonkProve {
}
interface MsgpackChonkVerify {
    proof: MsgpackChonkProof;
    vk: Uint8Array;
}
interface MsgpackChonkVerifyFromFields {
    proof: Uint8Array[];
    vk: Uint8Array;
}
interface MsgpackChonkBatchVerify {
    proofs: MsgpackChonkProof[];
    vks: Uint8Array[];
}
interface MsgpackVkAsFields {
    verification_key: Uint8Array;
}
interface MsgpackMegaVkAsFields {
    verification_key: Uint8Array;
}
interface MsgpackMegaAppVkAsFields {
    verification_key: Uint8Array;
}
interface MsgpackMegaKernelVkAsFields {
    verification_key: Uint8Array;
}
interface MsgpackMegaZKVkAsFields {
    verification_key: Uint8Array;
}
interface MsgpackCircuitWriteSolidityVerifier {
    verification_key: Uint8Array;
    settings: MsgpackProofSystemSettings;
}
interface MsgpackChonkCheckPrecomputedVk {
    circuit: MsgpackCircuitInput;
    kind: number;
}
interface MsgpackChonkStats {
    circuit: MsgpackCircuitInputNoVK;
    include_gates_per_opcode: boolean;
}
interface MsgpackChonkCompressProof {
    proof: MsgpackChonkProof;
}
interface MsgpackChonkDecompressProof {
    compressed_proof: Uint8Array;
}
interface MsgpackPoseidon2Hash {
    inputs: Uint8Array[];
}
interface MsgpackPoseidon2Permutation {
    inputs: Uint8Array[];
}
interface MsgpackPoseidon2AbsorbChain {
    state: Uint8Array[];
    inputs: Uint8Array;
}
interface MsgpackPedersenCommit {
    inputs: Uint8Array[];
    hash_index: number;
}
interface MsgpackPedersenHash {
    inputs: Uint8Array[];
    hash_index: number;
}
interface MsgpackBlake2s {
    data: Uint8Array;
}
interface MsgpackBlake2sToField {
    data: Uint8Array;
}
interface MsgpackAesEncrypt {
    plaintext: Uint8Array;
    iv: Uint8Array;
    key: Uint8Array;
    length: number;
}
interface MsgpackAesDecrypt {
    ciphertext: Uint8Array;
    iv: Uint8Array;
    key: Uint8Array;
    length: number;
}
interface MsgpackGrumpkinMul {
    point: MsgpackGrumpkinPoint;
    scalar: Uint8Array;
}
interface MsgpackGrumpkinAdd {
    point_a: MsgpackGrumpkinPoint;
    point_b: MsgpackGrumpkinPoint;
}
interface MsgpackGrumpkinBatchMul {
    points: MsgpackGrumpkinPoint[];
    scalar: Uint8Array;
}
interface MsgpackGrumpkinGetRandomFr {
    dummy: number;
}
interface MsgpackGrumpkinReduce512 {
    input: Uint8Array;
}
interface MsgpackSecp256k1Mul {
    point: MsgpackSecp256k1Point;
    scalar: Uint8Array;
}
interface MsgpackSecp256k1GetRandomFr {
    dummy: number;
}
interface MsgpackSecp256k1Reduce512 {
    input: Uint8Array;
}
interface MsgpackBn254FrSqrt {
    input: Uint8Array;
}
interface MsgpackBn254FqSqrt {
    input: Uint8Array;
}
interface MsgpackBn254G1Mul {
    point: MsgpackBn254G1Point;
    scalar: Uint8Array;
}
interface MsgpackBn254G2Mul {
    point: MsgpackBn254G2Point;
    scalar: Uint8Array;
}
interface MsgpackBn254G1IsOnCurve {
    point: MsgpackBn254G1Point;
}
interface MsgpackBn254G1FromCompressed {
    compressed: Uint8Array;
}
interface MsgpackSchnorrComputePublicKey {
    private_key: Uint8Array;
}
interface MsgpackSchnorrConstructSignature {
    message_field: Uint8Array;
    private_key: Uint8Array;
}
interface MsgpackSchnorrVerifySignature {
    message_field: Uint8Array;
    public_key: MsgpackGrumpkinPoint;
    s: Uint8Array;
    e: Uint8Array;
}
interface MsgpackEcdsaSecp256k1ComputePublicKey {
    private_key: Uint8Array;
}
interface MsgpackEcdsaSecp256r1ComputePublicKey {
    private_key: Uint8Array;
}
interface MsgpackEcdsaSecp256k1ConstructSignature {
    message: Uint8Array;
    private_key: Uint8Array;
}
interface MsgpackEcdsaSecp256r1ConstructSignature {
    message: Uint8Array;
    private_key: Uint8Array;
}
interface MsgpackEcdsaSecp256k1RecoverPublicKey {
    message: Uint8Array;
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
interface MsgpackEcdsaSecp256r1RecoverPublicKey {
    message: Uint8Array;
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
interface MsgpackEcdsaSecp256k1VerifySignature {
    message: Uint8Array;
    public_key: MsgpackSecp256k1Point;
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
interface MsgpackEcdsaSecp256r1VerifySignature {
    message: Uint8Array;
    public_key: MsgpackSecp256r1Point;
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
interface MsgpackSrsInitSrs {
    points_buf: Uint8Array;
    num_points: number;
    g2_point: Uint8Array;
}
interface MsgpackChonkBatchVerifierStart {
    vks: Uint8Array[];
    num_cores: number;
    batch_size: number;
    fifo_path: string;
}
interface MsgpackChonkBatchVerifierQueue {
    request_id: number | bigint;
    vk_index: number;
    proof_fields: Uint8Array[];
}
interface MsgpackChonkBatchVerifierStop {
}
interface MsgpackSrsInitGrumpkinSrs {
    points_buf: Uint8Array;
    num_points: number;
}
interface MsgpackInit {
    warmup: boolean | null;
}
interface MsgpackAvmProveResponse {
    proof: Uint8Array[];
    stats: MsgpackAvmStat[];
}
interface MsgpackAvmVerifyResponse {
    verified: boolean;
}
interface MsgpackAvmCheckCircuitResponse {
    passed: boolean;
    stats: MsgpackAvmStat[];
}
interface MsgpackCircuitProveResponse {
    public_inputs: Uint8Array[];
    proof: Uint8Array[];
    vk: MsgpackVkData;
}
interface MsgpackCircuitComputeVkResponse {
    bytes: Uint8Array;
    fields: Uint8Array[];
    hash: Uint8Array;
}
interface MsgpackCircuitStatsResponse {
    num_gates: number;
    num_gates_dyadic: number;
    num_acir_opcodes: number;
    gates_per_opcode: number[];
}
interface MsgpackCircuitVerifyResponse {
    verified: boolean;
}
interface MsgpackChonkComputeVkResponse {
    bytes: Uint8Array;
    fields: Uint8Array[];
}
interface MsgpackChonkStartResponse {
}
interface MsgpackChonkLoadResponse {
}
interface MsgpackChonkAccumulateResponse {
}
interface MsgpackChonkProveResponse {
    proof: MsgpackChonkProof;
}
interface MsgpackChonkVerifyResponse {
    valid: boolean;
}
interface MsgpackChonkVerifyFromFieldsResponse {
    valid: boolean;
}
interface MsgpackChonkBatchVerifyResponse {
    valid: boolean;
}
interface MsgpackVkAsFieldsResponse {
    fields: Uint8Array[];
}
interface MsgpackMegaVkAsFieldsResponse {
    fields: Uint8Array[];
}
interface MsgpackMegaAppVkAsFieldsResponse {
    fields: Uint8Array[];
}
interface MsgpackMegaKernelVkAsFieldsResponse {
    fields: Uint8Array[];
}
interface MsgpackMegaZKVkAsFieldsResponse {
    fields: Uint8Array[];
}
interface MsgpackCircuitWriteSolidityVerifierResponse {
    solidity_code: string;
}
interface MsgpackChonkCheckPrecomputedVkResponse {
    valid: boolean;
    actual_vk: Uint8Array;
}
interface MsgpackChonkStatsResponse {
    acir_opcodes: number;
    circuit_size: number;
    gates_per_opcode: number[];
}
interface MsgpackChonkCompressProofResponse {
    compressed_proof: Uint8Array;
}
interface MsgpackChonkDecompressProofResponse {
    proof: MsgpackChonkProof;
}
interface MsgpackPoseidon2HashResponse {
    hash: Uint8Array;
}
interface MsgpackPoseidon2PermutationResponse {
    outputs: Uint8Array[];
}
interface MsgpackPoseidon2AbsorbChainResponse {
    state: Uint8Array[];
}
interface MsgpackPedersenCommitResponse {
    point: MsgpackGrumpkinPoint;
}
interface MsgpackPedersenHashResponse {
    hash: Uint8Array;
}
interface MsgpackBlake2sResponse {
    hash: Uint8Array;
}
interface MsgpackBlake2sToFieldResponse {
    field: Uint8Array;
}
interface MsgpackAesEncryptResponse {
    ciphertext: Uint8Array;
}
interface MsgpackAesDecryptResponse {
    plaintext: Uint8Array;
}
interface MsgpackGrumpkinMulResponse {
    point: MsgpackGrumpkinPoint;
}
interface MsgpackGrumpkinAddResponse {
    point: MsgpackGrumpkinPoint;
}
interface MsgpackGrumpkinBatchMulResponse {
    points: MsgpackGrumpkinPoint[];
}
interface MsgpackGrumpkinGetRandomFrResponse {
    value: Uint8Array;
}
interface MsgpackGrumpkinReduce512Response {
    value: Uint8Array;
}
interface MsgpackSecp256k1MulResponse {
    point: MsgpackSecp256k1Point;
}
interface MsgpackSecp256k1GetRandomFrResponse {
    value: Uint8Array;
}
interface MsgpackSecp256k1Reduce512Response {
    value: Uint8Array;
}
interface MsgpackBn254FrSqrtResponse {
    is_square_root: boolean;
    value: Uint8Array;
}
interface MsgpackBn254FqSqrtResponse {
    is_square_root: boolean;
    value: Uint8Array;
}
interface MsgpackBn254G1MulResponse {
    point: MsgpackBn254G1Point;
}
interface MsgpackBn254G2MulResponse {
    point: MsgpackBn254G2Point;
}
interface MsgpackBn254G1IsOnCurveResponse {
    is_on_curve: boolean;
}
interface MsgpackBn254G1FromCompressedResponse {
    point: MsgpackBn254G1Point;
}
interface MsgpackSchnorrComputePublicKeyResponse {
    public_key: MsgpackGrumpkinPoint;
}
interface MsgpackSchnorrConstructSignatureResponse {
    s: Uint8Array;
    e: Uint8Array;
}
interface MsgpackSchnorrVerifySignatureResponse {
    verified: boolean;
}
interface MsgpackEcdsaSecp256k1ComputePublicKeyResponse {
    public_key: MsgpackSecp256k1Point;
}
interface MsgpackEcdsaSecp256r1ComputePublicKeyResponse {
    public_key: MsgpackSecp256r1Point;
}
interface MsgpackEcdsaSecp256k1ConstructSignatureResponse {
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
interface MsgpackEcdsaSecp256r1ConstructSignatureResponse {
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
interface MsgpackEcdsaSecp256k1RecoverPublicKeyResponse {
    public_key: MsgpackSecp256k1Point;
}
interface MsgpackEcdsaSecp256r1RecoverPublicKeyResponse {
    public_key: MsgpackSecp256r1Point;
}
interface MsgpackEcdsaSecp256k1VerifySignatureResponse {
    verified: boolean;
}
interface MsgpackEcdsaSecp256r1VerifySignatureResponse {
    verified: boolean;
}
interface MsgpackSrsInitSrsResponse {
    points_buf: Uint8Array;
}
interface MsgpackChonkBatchVerifierStartResponse {
}
interface MsgpackChonkBatchVerifierQueueResponse {
}
interface MsgpackChonkBatchVerifierStopResponse {
}
interface MsgpackSrsInitGrumpkinSrsResponse {
    dummy: number;
}
interface MsgpackInitResponse {
}
interface MsgpackErrorResponse {
    message: string;
}
export declare function toAvmStat(o: MsgpackAvmStat): AvmStat;
export declare function toVkData(o: MsgpackVkData): VkData;
export declare function toChonkProof(o: MsgpackChonkProof): ChonkProof;
export declare function toGrumpkinPoint(o: MsgpackGrumpkinPoint): GrumpkinPoint;
export declare function toSecp256k1Point(o: MsgpackSecp256k1Point): Secp256k1Point;
export declare function toBn254G1Point(o: MsgpackBn254G1Point): Bn254G1Point;
export declare function toBn254G2Point(o: MsgpackBn254G2Point): Bn254G2Point;
export declare function toSecp256r1Point(o: MsgpackSecp256r1Point): Secp256r1Point;
export declare function toAvmProve(o: MsgpackAvmProve): AvmProve;
export declare function toAvmVerify(o: MsgpackAvmVerify): AvmVerify;
export declare function toAvmCheckCircuit(o: MsgpackAvmCheckCircuit): AvmCheckCircuit;
export declare function toCircuitInput(o: MsgpackCircuitInput): CircuitInput;
export declare function toProofSystemSettings(o: MsgpackProofSystemSettings): ProofSystemSettings;
export declare function toCircuitProve(o: MsgpackCircuitProve): CircuitProve;
export declare function toCircuitInputNoVK(o: MsgpackCircuitInputNoVK): CircuitInputNoVK;
export declare function toCircuitComputeVk(o: MsgpackCircuitComputeVk): CircuitComputeVk;
export declare function toCircuitStats(o: MsgpackCircuitStats): CircuitStats;
export declare function toCircuitVerify(o: MsgpackCircuitVerify): CircuitVerify;
export declare function toChonkComputeVk(o: MsgpackChonkComputeVk): ChonkComputeVk;
export declare function toChonkStart(o: MsgpackChonkStart): ChonkStart;
export declare function toChonkLoad(o: MsgpackChonkLoad): ChonkLoad;
export declare function toChonkAccumulate(o: MsgpackChonkAccumulate): ChonkAccumulate;
export declare function toChonkProve(o: MsgpackChonkProve): ChonkProve;
export declare function toChonkVerify(o: MsgpackChonkVerify): ChonkVerify;
export declare function toChonkVerifyFromFields(o: MsgpackChonkVerifyFromFields): ChonkVerifyFromFields;
export declare function toChonkBatchVerify(o: MsgpackChonkBatchVerify): ChonkBatchVerify;
export declare function toVkAsFields(o: MsgpackVkAsFields): VkAsFields;
export declare function toMegaVkAsFields(o: MsgpackMegaVkAsFields): MegaVkAsFields;
export declare function toMegaAppVkAsFields(o: MsgpackMegaAppVkAsFields): MegaAppVkAsFields;
export declare function toMegaKernelVkAsFields(o: MsgpackMegaKernelVkAsFields): MegaKernelVkAsFields;
export declare function toMegaZKVkAsFields(o: MsgpackMegaZKVkAsFields): MegaZKVkAsFields;
export declare function toCircuitWriteSolidityVerifier(o: MsgpackCircuitWriteSolidityVerifier): CircuitWriteSolidityVerifier;
export declare function toChonkCheckPrecomputedVk(o: MsgpackChonkCheckPrecomputedVk): ChonkCheckPrecomputedVk;
export declare function toChonkStats(o: MsgpackChonkStats): ChonkStats;
export declare function toChonkCompressProof(o: MsgpackChonkCompressProof): ChonkCompressProof;
export declare function toChonkDecompressProof(o: MsgpackChonkDecompressProof): ChonkDecompressProof;
export declare function toPoseidon2Hash(o: MsgpackPoseidon2Hash): Poseidon2Hash;
export declare function toPoseidon2Permutation(o: MsgpackPoseidon2Permutation): Poseidon2Permutation;
export declare function toPoseidon2AbsorbChain(o: MsgpackPoseidon2AbsorbChain): Poseidon2AbsorbChain;
export declare function toPedersenCommit(o: MsgpackPedersenCommit): PedersenCommit;
export declare function toPedersenHash(o: MsgpackPedersenHash): PedersenHash;
export declare function toBlake2s(o: MsgpackBlake2s): Blake2s;
export declare function toBlake2sToField(o: MsgpackBlake2sToField): Blake2sToField;
export declare function toAesEncrypt(o: MsgpackAesEncrypt): AesEncrypt;
export declare function toAesDecrypt(o: MsgpackAesDecrypt): AesDecrypt;
export declare function toGrumpkinMul(o: MsgpackGrumpkinMul): GrumpkinMul;
export declare function toGrumpkinAdd(o: MsgpackGrumpkinAdd): GrumpkinAdd;
export declare function toGrumpkinBatchMul(o: MsgpackGrumpkinBatchMul): GrumpkinBatchMul;
export declare function toGrumpkinGetRandomFr(o: MsgpackGrumpkinGetRandomFr): GrumpkinGetRandomFr;
export declare function toGrumpkinReduce512(o: MsgpackGrumpkinReduce512): GrumpkinReduce512;
export declare function toSecp256k1Mul(o: MsgpackSecp256k1Mul): Secp256k1Mul;
export declare function toSecp256k1GetRandomFr(o: MsgpackSecp256k1GetRandomFr): Secp256k1GetRandomFr;
export declare function toSecp256k1Reduce512(o: MsgpackSecp256k1Reduce512): Secp256k1Reduce512;
export declare function toBn254FrSqrt(o: MsgpackBn254FrSqrt): Bn254FrSqrt;
export declare function toBn254FqSqrt(o: MsgpackBn254FqSqrt): Bn254FqSqrt;
export declare function toBn254G1Mul(o: MsgpackBn254G1Mul): Bn254G1Mul;
export declare function toBn254G2Mul(o: MsgpackBn254G2Mul): Bn254G2Mul;
export declare function toBn254G1IsOnCurve(o: MsgpackBn254G1IsOnCurve): Bn254G1IsOnCurve;
export declare function toBn254G1FromCompressed(o: MsgpackBn254G1FromCompressed): Bn254G1FromCompressed;
export declare function toSchnorrComputePublicKey(o: MsgpackSchnorrComputePublicKey): SchnorrComputePublicKey;
export declare function toSchnorrConstructSignature(o: MsgpackSchnorrConstructSignature): SchnorrConstructSignature;
export declare function toSchnorrVerifySignature(o: MsgpackSchnorrVerifySignature): SchnorrVerifySignature;
export declare function toEcdsaSecp256k1ComputePublicKey(o: MsgpackEcdsaSecp256k1ComputePublicKey): EcdsaSecp256k1ComputePublicKey;
export declare function toEcdsaSecp256r1ComputePublicKey(o: MsgpackEcdsaSecp256r1ComputePublicKey): EcdsaSecp256r1ComputePublicKey;
export declare function toEcdsaSecp256k1ConstructSignature(o: MsgpackEcdsaSecp256k1ConstructSignature): EcdsaSecp256k1ConstructSignature;
export declare function toEcdsaSecp256r1ConstructSignature(o: MsgpackEcdsaSecp256r1ConstructSignature): EcdsaSecp256r1ConstructSignature;
export declare function toEcdsaSecp256k1RecoverPublicKey(o: MsgpackEcdsaSecp256k1RecoverPublicKey): EcdsaSecp256k1RecoverPublicKey;
export declare function toEcdsaSecp256r1RecoverPublicKey(o: MsgpackEcdsaSecp256r1RecoverPublicKey): EcdsaSecp256r1RecoverPublicKey;
export declare function toEcdsaSecp256k1VerifySignature(o: MsgpackEcdsaSecp256k1VerifySignature): EcdsaSecp256k1VerifySignature;
export declare function toEcdsaSecp256r1VerifySignature(o: MsgpackEcdsaSecp256r1VerifySignature): EcdsaSecp256r1VerifySignature;
export declare function toSrsInitSrs(o: MsgpackSrsInitSrs): SrsInitSrs;
export declare function toChonkBatchVerifierStart(o: MsgpackChonkBatchVerifierStart): ChonkBatchVerifierStart;
export declare function toChonkBatchVerifierQueue(o: MsgpackChonkBatchVerifierQueue): ChonkBatchVerifierQueue;
export declare function toChonkBatchVerifierStop(o: MsgpackChonkBatchVerifierStop): ChonkBatchVerifierStop;
export declare function toSrsInitGrumpkinSrs(o: MsgpackSrsInitGrumpkinSrs): SrsInitGrumpkinSrs;
export declare function toInit(o: MsgpackInit): Init;
export declare function toAvmProveResponse(o: MsgpackAvmProveResponse): AvmProveResponse;
export declare function toAvmVerifyResponse(o: MsgpackAvmVerifyResponse): AvmVerifyResponse;
export declare function toAvmCheckCircuitResponse(o: MsgpackAvmCheckCircuitResponse): AvmCheckCircuitResponse;
export declare function toCircuitProveResponse(o: MsgpackCircuitProveResponse): CircuitProveResponse;
export declare function toCircuitComputeVkResponse(o: MsgpackCircuitComputeVkResponse): CircuitComputeVkResponse;
export declare function toCircuitStatsResponse(o: MsgpackCircuitStatsResponse): CircuitStatsResponse;
export declare function toCircuitVerifyResponse(o: MsgpackCircuitVerifyResponse): CircuitVerifyResponse;
export declare function toChonkComputeVkResponse(o: MsgpackChonkComputeVkResponse): ChonkComputeVkResponse;
export declare function toChonkStartResponse(o: MsgpackChonkStartResponse): ChonkStartResponse;
export declare function toChonkLoadResponse(o: MsgpackChonkLoadResponse): ChonkLoadResponse;
export declare function toChonkAccumulateResponse(o: MsgpackChonkAccumulateResponse): ChonkAccumulateResponse;
export declare function toChonkProveResponse(o: MsgpackChonkProveResponse): ChonkProveResponse;
export declare function toChonkVerifyResponse(o: MsgpackChonkVerifyResponse): ChonkVerifyResponse;
export declare function toChonkVerifyFromFieldsResponse(o: MsgpackChonkVerifyFromFieldsResponse): ChonkVerifyFromFieldsResponse;
export declare function toChonkBatchVerifyResponse(o: MsgpackChonkBatchVerifyResponse): ChonkBatchVerifyResponse;
export declare function toVkAsFieldsResponse(o: MsgpackVkAsFieldsResponse): VkAsFieldsResponse;
export declare function toMegaVkAsFieldsResponse(o: MsgpackMegaVkAsFieldsResponse): MegaVkAsFieldsResponse;
export declare function toMegaAppVkAsFieldsResponse(o: MsgpackMegaAppVkAsFieldsResponse): MegaAppVkAsFieldsResponse;
export declare function toMegaKernelVkAsFieldsResponse(o: MsgpackMegaKernelVkAsFieldsResponse): MegaKernelVkAsFieldsResponse;
export declare function toMegaZKVkAsFieldsResponse(o: MsgpackMegaZKVkAsFieldsResponse): MegaZKVkAsFieldsResponse;
export declare function toCircuitWriteSolidityVerifierResponse(o: MsgpackCircuitWriteSolidityVerifierResponse): CircuitWriteSolidityVerifierResponse;
export declare function toChonkCheckPrecomputedVkResponse(o: MsgpackChonkCheckPrecomputedVkResponse): ChonkCheckPrecomputedVkResponse;
export declare function toChonkStatsResponse(o: MsgpackChonkStatsResponse): ChonkStatsResponse;
export declare function toChonkCompressProofResponse(o: MsgpackChonkCompressProofResponse): ChonkCompressProofResponse;
export declare function toChonkDecompressProofResponse(o: MsgpackChonkDecompressProofResponse): ChonkDecompressProofResponse;
export declare function toPoseidon2HashResponse(o: MsgpackPoseidon2HashResponse): Poseidon2HashResponse;
export declare function toPoseidon2PermutationResponse(o: MsgpackPoseidon2PermutationResponse): Poseidon2PermutationResponse;
export declare function toPoseidon2AbsorbChainResponse(o: MsgpackPoseidon2AbsorbChainResponse): Poseidon2AbsorbChainResponse;
export declare function toPedersenCommitResponse(o: MsgpackPedersenCommitResponse): PedersenCommitResponse;
export declare function toPedersenHashResponse(o: MsgpackPedersenHashResponse): PedersenHashResponse;
export declare function toBlake2sResponse(o: MsgpackBlake2sResponse): Blake2sResponse;
export declare function toBlake2sToFieldResponse(o: MsgpackBlake2sToFieldResponse): Blake2sToFieldResponse;
export declare function toAesEncryptResponse(o: MsgpackAesEncryptResponse): AesEncryptResponse;
export declare function toAesDecryptResponse(o: MsgpackAesDecryptResponse): AesDecryptResponse;
export declare function toGrumpkinMulResponse(o: MsgpackGrumpkinMulResponse): GrumpkinMulResponse;
export declare function toGrumpkinAddResponse(o: MsgpackGrumpkinAddResponse): GrumpkinAddResponse;
export declare function toGrumpkinBatchMulResponse(o: MsgpackGrumpkinBatchMulResponse): GrumpkinBatchMulResponse;
export declare function toGrumpkinGetRandomFrResponse(o: MsgpackGrumpkinGetRandomFrResponse): GrumpkinGetRandomFrResponse;
export declare function toGrumpkinReduce512Response(o: MsgpackGrumpkinReduce512Response): GrumpkinReduce512Response;
export declare function toSecp256k1MulResponse(o: MsgpackSecp256k1MulResponse): Secp256k1MulResponse;
export declare function toSecp256k1GetRandomFrResponse(o: MsgpackSecp256k1GetRandomFrResponse): Secp256k1GetRandomFrResponse;
export declare function toSecp256k1Reduce512Response(o: MsgpackSecp256k1Reduce512Response): Secp256k1Reduce512Response;
export declare function toBn254FrSqrtResponse(o: MsgpackBn254FrSqrtResponse): Bn254FrSqrtResponse;
export declare function toBn254FqSqrtResponse(o: MsgpackBn254FqSqrtResponse): Bn254FqSqrtResponse;
export declare function toBn254G1MulResponse(o: MsgpackBn254G1MulResponse): Bn254G1MulResponse;
export declare function toBn254G2MulResponse(o: MsgpackBn254G2MulResponse): Bn254G2MulResponse;
export declare function toBn254G1IsOnCurveResponse(o: MsgpackBn254G1IsOnCurveResponse): Bn254G1IsOnCurveResponse;
export declare function toBn254G1FromCompressedResponse(o: MsgpackBn254G1FromCompressedResponse): Bn254G1FromCompressedResponse;
export declare function toSchnorrComputePublicKeyResponse(o: MsgpackSchnorrComputePublicKeyResponse): SchnorrComputePublicKeyResponse;
export declare function toSchnorrConstructSignatureResponse(o: MsgpackSchnorrConstructSignatureResponse): SchnorrConstructSignatureResponse;
export declare function toSchnorrVerifySignatureResponse(o: MsgpackSchnorrVerifySignatureResponse): SchnorrVerifySignatureResponse;
export declare function toEcdsaSecp256k1ComputePublicKeyResponse(o: MsgpackEcdsaSecp256k1ComputePublicKeyResponse): EcdsaSecp256k1ComputePublicKeyResponse;
export declare function toEcdsaSecp256r1ComputePublicKeyResponse(o: MsgpackEcdsaSecp256r1ComputePublicKeyResponse): EcdsaSecp256r1ComputePublicKeyResponse;
export declare function toEcdsaSecp256k1ConstructSignatureResponse(o: MsgpackEcdsaSecp256k1ConstructSignatureResponse): EcdsaSecp256k1ConstructSignatureResponse;
export declare function toEcdsaSecp256r1ConstructSignatureResponse(o: MsgpackEcdsaSecp256r1ConstructSignatureResponse): EcdsaSecp256r1ConstructSignatureResponse;
export declare function toEcdsaSecp256k1RecoverPublicKeyResponse(o: MsgpackEcdsaSecp256k1RecoverPublicKeyResponse): EcdsaSecp256k1RecoverPublicKeyResponse;
export declare function toEcdsaSecp256r1RecoverPublicKeyResponse(o: MsgpackEcdsaSecp256r1RecoverPublicKeyResponse): EcdsaSecp256r1RecoverPublicKeyResponse;
export declare function toEcdsaSecp256k1VerifySignatureResponse(o: MsgpackEcdsaSecp256k1VerifySignatureResponse): EcdsaSecp256k1VerifySignatureResponse;
export declare function toEcdsaSecp256r1VerifySignatureResponse(o: MsgpackEcdsaSecp256r1VerifySignatureResponse): EcdsaSecp256r1VerifySignatureResponse;
export declare function toSrsInitSrsResponse(o: MsgpackSrsInitSrsResponse): SrsInitSrsResponse;
export declare function toChonkBatchVerifierStartResponse(o: MsgpackChonkBatchVerifierStartResponse): ChonkBatchVerifierStartResponse;
export declare function toChonkBatchVerifierQueueResponse(o: MsgpackChonkBatchVerifierQueueResponse): ChonkBatchVerifierQueueResponse;
export declare function toChonkBatchVerifierStopResponse(o: MsgpackChonkBatchVerifierStopResponse): ChonkBatchVerifierStopResponse;
export declare function toSrsInitGrumpkinSrsResponse(o: MsgpackSrsInitGrumpkinSrsResponse): SrsInitGrumpkinSrsResponse;
export declare function toInitResponse(o: MsgpackInitResponse): InitResponse;
export declare function toErrorResponse(o: MsgpackErrorResponse): ErrorResponse;
export declare function fromAvmStat(o: AvmStat): MsgpackAvmStat;
export declare function fromVkData(o: VkData): MsgpackVkData;
export declare function fromChonkProof(o: ChonkProof): MsgpackChonkProof;
export declare function fromGrumpkinPoint(o: GrumpkinPoint): MsgpackGrumpkinPoint;
export declare function fromSecp256k1Point(o: Secp256k1Point): MsgpackSecp256k1Point;
export declare function fromBn254G1Point(o: Bn254G1Point): MsgpackBn254G1Point;
export declare function fromBn254G2Point(o: Bn254G2Point): MsgpackBn254G2Point;
export declare function fromSecp256r1Point(o: Secp256r1Point): MsgpackSecp256r1Point;
export declare function fromAvmProve(o: AvmProve): MsgpackAvmProve;
export declare function fromAvmVerify(o: AvmVerify): MsgpackAvmVerify;
export declare function fromAvmCheckCircuit(o: AvmCheckCircuit): MsgpackAvmCheckCircuit;
export declare function fromCircuitInput(o: CircuitInput): MsgpackCircuitInput;
export declare function fromProofSystemSettings(o: ProofSystemSettings): MsgpackProofSystemSettings;
export declare function fromCircuitProve(o: CircuitProve): MsgpackCircuitProve;
export declare function fromCircuitInputNoVK(o: CircuitInputNoVK): MsgpackCircuitInputNoVK;
export declare function fromCircuitComputeVk(o: CircuitComputeVk): MsgpackCircuitComputeVk;
export declare function fromCircuitStats(o: CircuitStats): MsgpackCircuitStats;
export declare function fromCircuitVerify(o: CircuitVerify): MsgpackCircuitVerify;
export declare function fromChonkComputeVk(o: ChonkComputeVk): MsgpackChonkComputeVk;
export declare function fromChonkStart(o: ChonkStart): MsgpackChonkStart;
export declare function fromChonkLoad(o: ChonkLoad): MsgpackChonkLoad;
export declare function fromChonkAccumulate(o: ChonkAccumulate): MsgpackChonkAccumulate;
export declare function fromChonkProve(o: ChonkProve): MsgpackChonkProve;
export declare function fromChonkVerify(o: ChonkVerify): MsgpackChonkVerify;
export declare function fromChonkVerifyFromFields(o: ChonkVerifyFromFields): MsgpackChonkVerifyFromFields;
export declare function fromChonkBatchVerify(o: ChonkBatchVerify): MsgpackChonkBatchVerify;
export declare function fromVkAsFields(o: VkAsFields): MsgpackVkAsFields;
export declare function fromMegaVkAsFields(o: MegaVkAsFields): MsgpackMegaVkAsFields;
export declare function fromMegaAppVkAsFields(o: MegaAppVkAsFields): MsgpackMegaAppVkAsFields;
export declare function fromMegaKernelVkAsFields(o: MegaKernelVkAsFields): MsgpackMegaKernelVkAsFields;
export declare function fromMegaZKVkAsFields(o: MegaZKVkAsFields): MsgpackMegaZKVkAsFields;
export declare function fromCircuitWriteSolidityVerifier(o: CircuitWriteSolidityVerifier): MsgpackCircuitWriteSolidityVerifier;
export declare function fromChonkCheckPrecomputedVk(o: ChonkCheckPrecomputedVk): MsgpackChonkCheckPrecomputedVk;
export declare function fromChonkStats(o: ChonkStats): MsgpackChonkStats;
export declare function fromChonkCompressProof(o: ChonkCompressProof): MsgpackChonkCompressProof;
export declare function fromChonkDecompressProof(o: ChonkDecompressProof): MsgpackChonkDecompressProof;
export declare function fromPoseidon2Hash(o: Poseidon2Hash): MsgpackPoseidon2Hash;
export declare function fromPoseidon2Permutation(o: Poseidon2Permutation): MsgpackPoseidon2Permutation;
export declare function fromPoseidon2AbsorbChain(o: Poseidon2AbsorbChain): MsgpackPoseidon2AbsorbChain;
export declare function fromPedersenCommit(o: PedersenCommit): MsgpackPedersenCommit;
export declare function fromPedersenHash(o: PedersenHash): MsgpackPedersenHash;
export declare function fromBlake2s(o: Blake2s): MsgpackBlake2s;
export declare function fromBlake2sToField(o: Blake2sToField): MsgpackBlake2sToField;
export declare function fromAesEncrypt(o: AesEncrypt): MsgpackAesEncrypt;
export declare function fromAesDecrypt(o: AesDecrypt): MsgpackAesDecrypt;
export declare function fromGrumpkinMul(o: GrumpkinMul): MsgpackGrumpkinMul;
export declare function fromGrumpkinAdd(o: GrumpkinAdd): MsgpackGrumpkinAdd;
export declare function fromGrumpkinBatchMul(o: GrumpkinBatchMul): MsgpackGrumpkinBatchMul;
export declare function fromGrumpkinGetRandomFr(o: GrumpkinGetRandomFr): MsgpackGrumpkinGetRandomFr;
export declare function fromGrumpkinReduce512(o: GrumpkinReduce512): MsgpackGrumpkinReduce512;
export declare function fromSecp256k1Mul(o: Secp256k1Mul): MsgpackSecp256k1Mul;
export declare function fromSecp256k1GetRandomFr(o: Secp256k1GetRandomFr): MsgpackSecp256k1GetRandomFr;
export declare function fromSecp256k1Reduce512(o: Secp256k1Reduce512): MsgpackSecp256k1Reduce512;
export declare function fromBn254FrSqrt(o: Bn254FrSqrt): MsgpackBn254FrSqrt;
export declare function fromBn254FqSqrt(o: Bn254FqSqrt): MsgpackBn254FqSqrt;
export declare function fromBn254G1Mul(o: Bn254G1Mul): MsgpackBn254G1Mul;
export declare function fromBn254G2Mul(o: Bn254G2Mul): MsgpackBn254G2Mul;
export declare function fromBn254G1IsOnCurve(o: Bn254G1IsOnCurve): MsgpackBn254G1IsOnCurve;
export declare function fromBn254G1FromCompressed(o: Bn254G1FromCompressed): MsgpackBn254G1FromCompressed;
export declare function fromSchnorrComputePublicKey(o: SchnorrComputePublicKey): MsgpackSchnorrComputePublicKey;
export declare function fromSchnorrConstructSignature(o: SchnorrConstructSignature): MsgpackSchnorrConstructSignature;
export declare function fromSchnorrVerifySignature(o: SchnorrVerifySignature): MsgpackSchnorrVerifySignature;
export declare function fromEcdsaSecp256k1ComputePublicKey(o: EcdsaSecp256k1ComputePublicKey): MsgpackEcdsaSecp256k1ComputePublicKey;
export declare function fromEcdsaSecp256r1ComputePublicKey(o: EcdsaSecp256r1ComputePublicKey): MsgpackEcdsaSecp256r1ComputePublicKey;
export declare function fromEcdsaSecp256k1ConstructSignature(o: EcdsaSecp256k1ConstructSignature): MsgpackEcdsaSecp256k1ConstructSignature;
export declare function fromEcdsaSecp256r1ConstructSignature(o: EcdsaSecp256r1ConstructSignature): MsgpackEcdsaSecp256r1ConstructSignature;
export declare function fromEcdsaSecp256k1RecoverPublicKey(o: EcdsaSecp256k1RecoverPublicKey): MsgpackEcdsaSecp256k1RecoverPublicKey;
export declare function fromEcdsaSecp256r1RecoverPublicKey(o: EcdsaSecp256r1RecoverPublicKey): MsgpackEcdsaSecp256r1RecoverPublicKey;
export declare function fromEcdsaSecp256k1VerifySignature(o: EcdsaSecp256k1VerifySignature): MsgpackEcdsaSecp256k1VerifySignature;
export declare function fromEcdsaSecp256r1VerifySignature(o: EcdsaSecp256r1VerifySignature): MsgpackEcdsaSecp256r1VerifySignature;
export declare function fromSrsInitSrs(o: SrsInitSrs): MsgpackSrsInitSrs;
export declare function fromChonkBatchVerifierStart(o: ChonkBatchVerifierStart): MsgpackChonkBatchVerifierStart;
export declare function fromChonkBatchVerifierQueue(o: ChonkBatchVerifierQueue): MsgpackChonkBatchVerifierQueue;
export declare function fromChonkBatchVerifierStop(o: ChonkBatchVerifierStop): MsgpackChonkBatchVerifierStop;
export declare function fromSrsInitGrumpkinSrs(o: SrsInitGrumpkinSrs): MsgpackSrsInitGrumpkinSrs;
export declare function fromInit(o: Init): MsgpackInit;
export declare function fromAvmProveResponse(o: AvmProveResponse): MsgpackAvmProveResponse;
export declare function fromAvmVerifyResponse(o: AvmVerifyResponse): MsgpackAvmVerifyResponse;
export declare function fromAvmCheckCircuitResponse(o: AvmCheckCircuitResponse): MsgpackAvmCheckCircuitResponse;
export declare function fromCircuitProveResponse(o: CircuitProveResponse): MsgpackCircuitProveResponse;
export declare function fromCircuitComputeVkResponse(o: CircuitComputeVkResponse): MsgpackCircuitComputeVkResponse;
export declare function fromCircuitStatsResponse(o: CircuitStatsResponse): MsgpackCircuitStatsResponse;
export declare function fromCircuitVerifyResponse(o: CircuitVerifyResponse): MsgpackCircuitVerifyResponse;
export declare function fromChonkComputeVkResponse(o: ChonkComputeVkResponse): MsgpackChonkComputeVkResponse;
export declare function fromChonkStartResponse(o: ChonkStartResponse): MsgpackChonkStartResponse;
export declare function fromChonkLoadResponse(o: ChonkLoadResponse): MsgpackChonkLoadResponse;
export declare function fromChonkAccumulateResponse(o: ChonkAccumulateResponse): MsgpackChonkAccumulateResponse;
export declare function fromChonkProveResponse(o: ChonkProveResponse): MsgpackChonkProveResponse;
export declare function fromChonkVerifyResponse(o: ChonkVerifyResponse): MsgpackChonkVerifyResponse;
export declare function fromChonkVerifyFromFieldsResponse(o: ChonkVerifyFromFieldsResponse): MsgpackChonkVerifyFromFieldsResponse;
export declare function fromChonkBatchVerifyResponse(o: ChonkBatchVerifyResponse): MsgpackChonkBatchVerifyResponse;
export declare function fromVkAsFieldsResponse(o: VkAsFieldsResponse): MsgpackVkAsFieldsResponse;
export declare function fromMegaVkAsFieldsResponse(o: MegaVkAsFieldsResponse): MsgpackMegaVkAsFieldsResponse;
export declare function fromMegaAppVkAsFieldsResponse(o: MegaAppVkAsFieldsResponse): MsgpackMegaAppVkAsFieldsResponse;
export declare function fromMegaKernelVkAsFieldsResponse(o: MegaKernelVkAsFieldsResponse): MsgpackMegaKernelVkAsFieldsResponse;
export declare function fromMegaZKVkAsFieldsResponse(o: MegaZKVkAsFieldsResponse): MsgpackMegaZKVkAsFieldsResponse;
export declare function fromCircuitWriteSolidityVerifierResponse(o: CircuitWriteSolidityVerifierResponse): MsgpackCircuitWriteSolidityVerifierResponse;
export declare function fromChonkCheckPrecomputedVkResponse(o: ChonkCheckPrecomputedVkResponse): MsgpackChonkCheckPrecomputedVkResponse;
export declare function fromChonkStatsResponse(o: ChonkStatsResponse): MsgpackChonkStatsResponse;
export declare function fromChonkCompressProofResponse(o: ChonkCompressProofResponse): MsgpackChonkCompressProofResponse;
export declare function fromChonkDecompressProofResponse(o: ChonkDecompressProofResponse): MsgpackChonkDecompressProofResponse;
export declare function fromPoseidon2HashResponse(o: Poseidon2HashResponse): MsgpackPoseidon2HashResponse;
export declare function fromPoseidon2PermutationResponse(o: Poseidon2PermutationResponse): MsgpackPoseidon2PermutationResponse;
export declare function fromPoseidon2AbsorbChainResponse(o: Poseidon2AbsorbChainResponse): MsgpackPoseidon2AbsorbChainResponse;
export declare function fromPedersenCommitResponse(o: PedersenCommitResponse): MsgpackPedersenCommitResponse;
export declare function fromPedersenHashResponse(o: PedersenHashResponse): MsgpackPedersenHashResponse;
export declare function fromBlake2sResponse(o: Blake2sResponse): MsgpackBlake2sResponse;
export declare function fromBlake2sToFieldResponse(o: Blake2sToFieldResponse): MsgpackBlake2sToFieldResponse;
export declare function fromAesEncryptResponse(o: AesEncryptResponse): MsgpackAesEncryptResponse;
export declare function fromAesDecryptResponse(o: AesDecryptResponse): MsgpackAesDecryptResponse;
export declare function fromGrumpkinMulResponse(o: GrumpkinMulResponse): MsgpackGrumpkinMulResponse;
export declare function fromGrumpkinAddResponse(o: GrumpkinAddResponse): MsgpackGrumpkinAddResponse;
export declare function fromGrumpkinBatchMulResponse(o: GrumpkinBatchMulResponse): MsgpackGrumpkinBatchMulResponse;
export declare function fromGrumpkinGetRandomFrResponse(o: GrumpkinGetRandomFrResponse): MsgpackGrumpkinGetRandomFrResponse;
export declare function fromGrumpkinReduce512Response(o: GrumpkinReduce512Response): MsgpackGrumpkinReduce512Response;
export declare function fromSecp256k1MulResponse(o: Secp256k1MulResponse): MsgpackSecp256k1MulResponse;
export declare function fromSecp256k1GetRandomFrResponse(o: Secp256k1GetRandomFrResponse): MsgpackSecp256k1GetRandomFrResponse;
export declare function fromSecp256k1Reduce512Response(o: Secp256k1Reduce512Response): MsgpackSecp256k1Reduce512Response;
export declare function fromBn254FrSqrtResponse(o: Bn254FrSqrtResponse): MsgpackBn254FrSqrtResponse;
export declare function fromBn254FqSqrtResponse(o: Bn254FqSqrtResponse): MsgpackBn254FqSqrtResponse;
export declare function fromBn254G1MulResponse(o: Bn254G1MulResponse): MsgpackBn254G1MulResponse;
export declare function fromBn254G2MulResponse(o: Bn254G2MulResponse): MsgpackBn254G2MulResponse;
export declare function fromBn254G1IsOnCurveResponse(o: Bn254G1IsOnCurveResponse): MsgpackBn254G1IsOnCurveResponse;
export declare function fromBn254G1FromCompressedResponse(o: Bn254G1FromCompressedResponse): MsgpackBn254G1FromCompressedResponse;
export declare function fromSchnorrComputePublicKeyResponse(o: SchnorrComputePublicKeyResponse): MsgpackSchnorrComputePublicKeyResponse;
export declare function fromSchnorrConstructSignatureResponse(o: SchnorrConstructSignatureResponse): MsgpackSchnorrConstructSignatureResponse;
export declare function fromSchnorrVerifySignatureResponse(o: SchnorrVerifySignatureResponse): MsgpackSchnorrVerifySignatureResponse;
export declare function fromEcdsaSecp256k1ComputePublicKeyResponse(o: EcdsaSecp256k1ComputePublicKeyResponse): MsgpackEcdsaSecp256k1ComputePublicKeyResponse;
export declare function fromEcdsaSecp256r1ComputePublicKeyResponse(o: EcdsaSecp256r1ComputePublicKeyResponse): MsgpackEcdsaSecp256r1ComputePublicKeyResponse;
export declare function fromEcdsaSecp256k1ConstructSignatureResponse(o: EcdsaSecp256k1ConstructSignatureResponse): MsgpackEcdsaSecp256k1ConstructSignatureResponse;
export declare function fromEcdsaSecp256r1ConstructSignatureResponse(o: EcdsaSecp256r1ConstructSignatureResponse): MsgpackEcdsaSecp256r1ConstructSignatureResponse;
export declare function fromEcdsaSecp256k1RecoverPublicKeyResponse(o: EcdsaSecp256k1RecoverPublicKeyResponse): MsgpackEcdsaSecp256k1RecoverPublicKeyResponse;
export declare function fromEcdsaSecp256r1RecoverPublicKeyResponse(o: EcdsaSecp256r1RecoverPublicKeyResponse): MsgpackEcdsaSecp256r1RecoverPublicKeyResponse;
export declare function fromEcdsaSecp256k1VerifySignatureResponse(o: EcdsaSecp256k1VerifySignatureResponse): MsgpackEcdsaSecp256k1VerifySignatureResponse;
export declare function fromEcdsaSecp256r1VerifySignatureResponse(o: EcdsaSecp256r1VerifySignatureResponse): MsgpackEcdsaSecp256r1VerifySignatureResponse;
export declare function fromSrsInitSrsResponse(o: SrsInitSrsResponse): MsgpackSrsInitSrsResponse;
export declare function fromChonkBatchVerifierStartResponse(o: ChonkBatchVerifierStartResponse): MsgpackChonkBatchVerifierStartResponse;
export declare function fromChonkBatchVerifierQueueResponse(o: ChonkBatchVerifierQueueResponse): MsgpackChonkBatchVerifierQueueResponse;
export declare function fromChonkBatchVerifierStopResponse(o: ChonkBatchVerifierStopResponse): MsgpackChonkBatchVerifierStopResponse;
export declare function fromSrsInitGrumpkinSrsResponse(o: SrsInitGrumpkinSrsResponse): MsgpackSrsInitGrumpkinSrsResponse;
export declare function fromInitResponse(o: InitResponse): MsgpackInitResponse;
export declare function fromErrorResponse(o: ErrorResponse): MsgpackErrorResponse;
/**
 * Thrown when the service answers a command with BbErrorResponse rather than a result.
 * The message is the service's own, so the type is what separates "the service said no" from a
 * fault in the client. Declared here so the async and sync APIs throw the same class.
 */
export declare class BbError extends Error {
    constructor(message: string);
}
export interface AsyncApiBase {
    avmProve(command: AvmProve): Promise<AvmProveResponse>;
    avmVerify(command: AvmVerify): Promise<AvmVerifyResponse>;
    avmCheckCircuit(command: AvmCheckCircuit): Promise<AvmCheckCircuitResponse>;
    circuitProve(command: CircuitProve): Promise<CircuitProveResponse>;
    circuitComputeVk(command: CircuitComputeVk): Promise<CircuitComputeVkResponse>;
    circuitStats(command: CircuitStats): Promise<CircuitStatsResponse>;
    circuitVerify(command: CircuitVerify): Promise<CircuitVerifyResponse>;
    chonkComputeVk(command: ChonkComputeVk): Promise<ChonkComputeVkResponse>;
    chonkStart(command: ChonkStart): Promise<ChonkStartResponse>;
    chonkLoad(command: ChonkLoad): Promise<ChonkLoadResponse>;
    chonkAccumulate(command: ChonkAccumulate): Promise<ChonkAccumulateResponse>;
    chonkProve(command: ChonkProve): Promise<ChonkProveResponse>;
    chonkVerify(command: ChonkVerify): Promise<ChonkVerifyResponse>;
    chonkVerifyFromFields(command: ChonkVerifyFromFields): Promise<ChonkVerifyFromFieldsResponse>;
    chonkBatchVerify(command: ChonkBatchVerify): Promise<ChonkBatchVerifyResponse>;
    vkAsFields(command: VkAsFields): Promise<VkAsFieldsResponse>;
    megaVkAsFields(command: MegaVkAsFields): Promise<MegaVkAsFieldsResponse>;
    megaAppVkAsFields(command: MegaAppVkAsFields): Promise<MegaAppVkAsFieldsResponse>;
    megaKernelVkAsFields(command: MegaKernelVkAsFields): Promise<MegaKernelVkAsFieldsResponse>;
    megaZKVkAsFields(command: MegaZKVkAsFields): Promise<MegaZKVkAsFieldsResponse>;
    circuitWriteSolidityVerifier(command: CircuitWriteSolidityVerifier): Promise<CircuitWriteSolidityVerifierResponse>;
    chonkCheckPrecomputedVk(command: ChonkCheckPrecomputedVk): Promise<ChonkCheckPrecomputedVkResponse>;
    chonkStats(command: ChonkStats): Promise<ChonkStatsResponse>;
    chonkCompressProof(command: ChonkCompressProof): Promise<ChonkCompressProofResponse>;
    chonkDecompressProof(command: ChonkDecompressProof): Promise<ChonkDecompressProofResponse>;
    poseidon2Hash(command: Poseidon2Hash): Promise<Poseidon2HashResponse>;
    poseidon2Permutation(command: Poseidon2Permutation): Promise<Poseidon2PermutationResponse>;
    poseidon2AbsorbChain(command: Poseidon2AbsorbChain): Promise<Poseidon2AbsorbChainResponse>;
    pedersenCommit(command: PedersenCommit): Promise<PedersenCommitResponse>;
    pedersenHash(command: PedersenHash): Promise<PedersenHashResponse>;
    blake2s(command: Blake2s): Promise<Blake2sResponse>;
    blake2sToField(command: Blake2sToField): Promise<Blake2sToFieldResponse>;
    aesEncrypt(command: AesEncrypt): Promise<AesEncryptResponse>;
    aesDecrypt(command: AesDecrypt): Promise<AesDecryptResponse>;
    grumpkinMul(command: GrumpkinMul): Promise<GrumpkinMulResponse>;
    grumpkinAdd(command: GrumpkinAdd): Promise<GrumpkinAddResponse>;
    grumpkinBatchMul(command: GrumpkinBatchMul): Promise<GrumpkinBatchMulResponse>;
    grumpkinGetRandomFr(command: GrumpkinGetRandomFr): Promise<GrumpkinGetRandomFrResponse>;
    grumpkinReduce512(command: GrumpkinReduce512): Promise<GrumpkinReduce512Response>;
    secp256k1Mul(command: Secp256k1Mul): Promise<Secp256k1MulResponse>;
    secp256k1GetRandomFr(command: Secp256k1GetRandomFr): Promise<Secp256k1GetRandomFrResponse>;
    secp256k1Reduce512(command: Secp256k1Reduce512): Promise<Secp256k1Reduce512Response>;
    bn254FrSqrt(command: Bn254FrSqrt): Promise<Bn254FrSqrtResponse>;
    bn254FqSqrt(command: Bn254FqSqrt): Promise<Bn254FqSqrtResponse>;
    bn254G1Mul(command: Bn254G1Mul): Promise<Bn254G1MulResponse>;
    bn254G2Mul(command: Bn254G2Mul): Promise<Bn254G2MulResponse>;
    bn254G1IsOnCurve(command: Bn254G1IsOnCurve): Promise<Bn254G1IsOnCurveResponse>;
    bn254G1FromCompressed(command: Bn254G1FromCompressed): Promise<Bn254G1FromCompressedResponse>;
    schnorrComputePublicKey(command: SchnorrComputePublicKey): Promise<SchnorrComputePublicKeyResponse>;
    schnorrConstructSignature(command: SchnorrConstructSignature): Promise<SchnorrConstructSignatureResponse>;
    schnorrVerifySignature(command: SchnorrVerifySignature): Promise<SchnorrVerifySignatureResponse>;
    ecdsaSecp256k1ComputePublicKey(command: EcdsaSecp256k1ComputePublicKey): Promise<EcdsaSecp256k1ComputePublicKeyResponse>;
    ecdsaSecp256r1ComputePublicKey(command: EcdsaSecp256r1ComputePublicKey): Promise<EcdsaSecp256r1ComputePublicKeyResponse>;
    ecdsaSecp256k1ConstructSignature(command: EcdsaSecp256k1ConstructSignature): Promise<EcdsaSecp256k1ConstructSignatureResponse>;
    ecdsaSecp256r1ConstructSignature(command: EcdsaSecp256r1ConstructSignature): Promise<EcdsaSecp256r1ConstructSignatureResponse>;
    ecdsaSecp256k1RecoverPublicKey(command: EcdsaSecp256k1RecoverPublicKey): Promise<EcdsaSecp256k1RecoverPublicKeyResponse>;
    ecdsaSecp256r1RecoverPublicKey(command: EcdsaSecp256r1RecoverPublicKey): Promise<EcdsaSecp256r1RecoverPublicKeyResponse>;
    ecdsaSecp256k1VerifySignature(command: EcdsaSecp256k1VerifySignature): Promise<EcdsaSecp256k1VerifySignatureResponse>;
    ecdsaSecp256r1VerifySignature(command: EcdsaSecp256r1VerifySignature): Promise<EcdsaSecp256r1VerifySignatureResponse>;
    srsInitSrs(command: SrsInitSrs): Promise<SrsInitSrsResponse>;
    chonkBatchVerifierStart(command: ChonkBatchVerifierStart): Promise<ChonkBatchVerifierStartResponse>;
    chonkBatchVerifierQueue(command: ChonkBatchVerifierQueue): Promise<ChonkBatchVerifierQueueResponse>;
    chonkBatchVerifierStop(command: ChonkBatchVerifierStop): Promise<ChonkBatchVerifierStopResponse>;
    srsInitGrumpkinSrs(command: SrsInitGrumpkinSrs): Promise<SrsInitGrumpkinSrsResponse>;
    init(command: Init): Promise<InitResponse>;
    destroy(): Promise<void>;
}
export interface SyncApiBase {
    avmProve(command: AvmProve): AvmProveResponse;
    avmVerify(command: AvmVerify): AvmVerifyResponse;
    avmCheckCircuit(command: AvmCheckCircuit): AvmCheckCircuitResponse;
    circuitProve(command: CircuitProve): CircuitProveResponse;
    circuitComputeVk(command: CircuitComputeVk): CircuitComputeVkResponse;
    circuitStats(command: CircuitStats): CircuitStatsResponse;
    circuitVerify(command: CircuitVerify): CircuitVerifyResponse;
    chonkComputeVk(command: ChonkComputeVk): ChonkComputeVkResponse;
    chonkStart(command: ChonkStart): ChonkStartResponse;
    chonkLoad(command: ChonkLoad): ChonkLoadResponse;
    chonkAccumulate(command: ChonkAccumulate): ChonkAccumulateResponse;
    chonkProve(command: ChonkProve): ChonkProveResponse;
    chonkVerify(command: ChonkVerify): ChonkVerifyResponse;
    chonkVerifyFromFields(command: ChonkVerifyFromFields): ChonkVerifyFromFieldsResponse;
    chonkBatchVerify(command: ChonkBatchVerify): ChonkBatchVerifyResponse;
    vkAsFields(command: VkAsFields): VkAsFieldsResponse;
    megaVkAsFields(command: MegaVkAsFields): MegaVkAsFieldsResponse;
    megaAppVkAsFields(command: MegaAppVkAsFields): MegaAppVkAsFieldsResponse;
    megaKernelVkAsFields(command: MegaKernelVkAsFields): MegaKernelVkAsFieldsResponse;
    megaZKVkAsFields(command: MegaZKVkAsFields): MegaZKVkAsFieldsResponse;
    circuitWriteSolidityVerifier(command: CircuitWriteSolidityVerifier): CircuitWriteSolidityVerifierResponse;
    chonkCheckPrecomputedVk(command: ChonkCheckPrecomputedVk): ChonkCheckPrecomputedVkResponse;
    chonkStats(command: ChonkStats): ChonkStatsResponse;
    chonkCompressProof(command: ChonkCompressProof): ChonkCompressProofResponse;
    chonkDecompressProof(command: ChonkDecompressProof): ChonkDecompressProofResponse;
    poseidon2Hash(command: Poseidon2Hash): Poseidon2HashResponse;
    poseidon2Permutation(command: Poseidon2Permutation): Poseidon2PermutationResponse;
    poseidon2AbsorbChain(command: Poseidon2AbsorbChain): Poseidon2AbsorbChainResponse;
    pedersenCommit(command: PedersenCommit): PedersenCommitResponse;
    pedersenHash(command: PedersenHash): PedersenHashResponse;
    blake2s(command: Blake2s): Blake2sResponse;
    blake2sToField(command: Blake2sToField): Blake2sToFieldResponse;
    aesEncrypt(command: AesEncrypt): AesEncryptResponse;
    aesDecrypt(command: AesDecrypt): AesDecryptResponse;
    grumpkinMul(command: GrumpkinMul): GrumpkinMulResponse;
    grumpkinAdd(command: GrumpkinAdd): GrumpkinAddResponse;
    grumpkinBatchMul(command: GrumpkinBatchMul): GrumpkinBatchMulResponse;
    grumpkinGetRandomFr(command: GrumpkinGetRandomFr): GrumpkinGetRandomFrResponse;
    grumpkinReduce512(command: GrumpkinReduce512): GrumpkinReduce512Response;
    secp256k1Mul(command: Secp256k1Mul): Secp256k1MulResponse;
    secp256k1GetRandomFr(command: Secp256k1GetRandomFr): Secp256k1GetRandomFrResponse;
    secp256k1Reduce512(command: Secp256k1Reduce512): Secp256k1Reduce512Response;
    bn254FrSqrt(command: Bn254FrSqrt): Bn254FrSqrtResponse;
    bn254FqSqrt(command: Bn254FqSqrt): Bn254FqSqrtResponse;
    bn254G1Mul(command: Bn254G1Mul): Bn254G1MulResponse;
    bn254G2Mul(command: Bn254G2Mul): Bn254G2MulResponse;
    bn254G1IsOnCurve(command: Bn254G1IsOnCurve): Bn254G1IsOnCurveResponse;
    bn254G1FromCompressed(command: Bn254G1FromCompressed): Bn254G1FromCompressedResponse;
    schnorrComputePublicKey(command: SchnorrComputePublicKey): SchnorrComputePublicKeyResponse;
    schnorrConstructSignature(command: SchnorrConstructSignature): SchnorrConstructSignatureResponse;
    schnorrVerifySignature(command: SchnorrVerifySignature): SchnorrVerifySignatureResponse;
    ecdsaSecp256k1ComputePublicKey(command: EcdsaSecp256k1ComputePublicKey): EcdsaSecp256k1ComputePublicKeyResponse;
    ecdsaSecp256r1ComputePublicKey(command: EcdsaSecp256r1ComputePublicKey): EcdsaSecp256r1ComputePublicKeyResponse;
    ecdsaSecp256k1ConstructSignature(command: EcdsaSecp256k1ConstructSignature): EcdsaSecp256k1ConstructSignatureResponse;
    ecdsaSecp256r1ConstructSignature(command: EcdsaSecp256r1ConstructSignature): EcdsaSecp256r1ConstructSignatureResponse;
    ecdsaSecp256k1RecoverPublicKey(command: EcdsaSecp256k1RecoverPublicKey): EcdsaSecp256k1RecoverPublicKeyResponse;
    ecdsaSecp256r1RecoverPublicKey(command: EcdsaSecp256r1RecoverPublicKey): EcdsaSecp256r1RecoverPublicKeyResponse;
    ecdsaSecp256k1VerifySignature(command: EcdsaSecp256k1VerifySignature): EcdsaSecp256k1VerifySignatureResponse;
    ecdsaSecp256r1VerifySignature(command: EcdsaSecp256r1VerifySignature): EcdsaSecp256r1VerifySignatureResponse;
    srsInitSrs(command: SrsInitSrs): SrsInitSrsResponse;
    chonkBatchVerifierStart(command: ChonkBatchVerifierStart): ChonkBatchVerifierStartResponse;
    chonkBatchVerifierQueue(command: ChonkBatchVerifierQueue): ChonkBatchVerifierQueueResponse;
    chonkBatchVerifierStop(command: ChonkBatchVerifierStop): ChonkBatchVerifierStopResponse;
    srsInitGrumpkinSrs(command: SrsInitGrumpkinSrs): SrsInitGrumpkinSrsResponse;
    init(command: Init): InitResponse;
    destroy(): void;
}
export {};
//# sourceMappingURL=api_types.d.ts.map
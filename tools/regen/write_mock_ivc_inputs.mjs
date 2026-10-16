// Write bb's `ivc-inputs.msgpack` for a mock-protocol transaction (yarn-project/ivc-integration's
// `generateTestingIVCStack`): one {bytecode, witness, vk, functionName, kind} per circuit, bytecode
// and witness gzipped. Usage: node write_mock_ivc_inputs.mjs <labs root (aztec-node checkout)> <#creator calls> <#reader calls> <out>
import { createRequire } from 'module';
import { writeFileSync } from 'fs';
import { gzipSync } from 'zlib';
import { pathToFileURL } from 'url';

const [root, numCreator, numReader, out] = process.argv.slice(2);
const ivc = `${root}/yarn-project/ivc-integration`;
const { generateTestingIVCStack } = await import(pathToFileURL(`${ivc}/dest/witgen.js`));
const { Encoder } = createRequire(`${ivc}/package.json`)('msgpackr');

const [bytecodes, witnesses, , vks, kinds] = await generateTestingIVCStack(Number(numCreator), Number(numReader));
const isGzip = b => b[0] === 0x1f && b[1] === 0x8b;
const gz = b => (isGzip(b) ? Buffer.from(b) : gzipSync(b));
const steps = bytecodes.map((bytecode, i) => ({
  bytecode: gz(Buffer.from(bytecode, 'base64')),
  witness: gz(witnesses[i]),
  vk: Buffer.from(vks[i], 'hex'),
  functionName: `circuit_${i}`,
  kind: kinds[i],
}));
writeFileSync(out, new Encoder({ useRecords: false }).pack(steps));
console.log(steps.map(s => `${s.functionName}:${s.kind}:${s.bytecode.length}b`).join(' '));

import { createHash, createPublicKey, verify } from 'node:crypto';

export type Release = {
  schema: 'sentinel-release/v1';
  version: string;
  artifactSha256: string;
  artifactBytes: number;
  engineAbi: string;
  keyId: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;
};

const digest = /^[a-f0-9]{64}$/;
const stamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const fields = ['schema','version','artifactSha256','artifactBytes','engineAbi','keyId','issuedAt','expiresAt','signature'];

export function releasePayload(input: unknown): Buffer {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid release');
  const r = input as Release;
  if (Object.keys(r).length !== fields.length || fields.some(k => !Object.hasOwn(r,k)) ||
      r.schema !== 'sentinel-release/v1' || !Number.isSafeInteger(r.artifactBytes) || r.artifactBytes < 1 ||
      typeof r.artifactSha256 !== 'string' || !digest.test(r.artifactSha256) ||
      ![r.version,r.engineAbi,r.keyId].every(v => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(v)) ||
      ![r.issuedAt,r.expiresAt].every(v => typeof v === 'string' && stamp.test(v) && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v) ||
      typeof r.signature !== 'string') throw new Error('Invalid release schema');
  // Fixed field order, UTF-8, domain separation; independent of input key order.
  return Buffer.from('sentinel-release/v1\n' + JSON.stringify([
    r.schema,r.version,r.artifactSha256,r.artifactBytes,r.engineAbi,r.keyId,r.issuedAt,r.expiresAt,
  ]));
}

export function verifyRelease(input: unknown, artifact: Uint8Array, policy: {
  trustedKeys: ReadonlyMap<string,string>;
  approvedDigest: string;
  engineAbi: string;
  revokedDigests: ReadonlySet<string>;
  maxArtifactBytes: number;
  now: Date;
}): Release {
  const payload = releasePayload(input), r = input as Release;
  if (!digest.test(policy.approvedDigest) || !Number.isSafeInteger(policy.maxArtifactBytes) ||
      policy.maxArtifactBytes < 1 || !Number.isFinite(policy.now.getTime())) throw new Error('Invalid import policy');
  if (r.artifactSha256 !== policy.approvedDigest) throw new Error('Manual approval required');
  if (policy.revokedDigests.has(r.artifactSha256)) throw new Error('Revoked artifact');
  if (r.engineAbi !== policy.engineAbi) throw new Error('Incompatible engine ABI');
  if (Date.parse(r.issuedAt) > policy.now.getTime() || Date.parse(r.expiresAt) <= policy.now.getTime() ||
      Date.parse(r.issuedAt) >= Date.parse(r.expiresAt)) throw new Error('Release outside validity window');
  const pem = policy.trustedKeys.get(r.keyId);
  if (!pem) throw new Error('Untrusted signing key');
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== 'ed25519' || !/^[A-Za-z0-9+/]{86}==$/.test(r.signature)) throw new Error('Invalid signature format');
  if (artifact.byteLength !== r.artifactBytes || artifact.byteLength > policy.maxArtifactBytes ||
      createHash('sha256').update(artifact).digest('hex') !== r.artifactSha256) throw new Error('Artifact integrity failure');
  if (!verify(null,payload,key,Buffer.from(r.signature,'base64'))) throw new Error('Invalid release signature');
  return Object.freeze({ ...r });
}

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";

/**
 * Generates an Ed25519 key pair. Writes the private key as PEM (mode 0600) and the
 * public key as a JWK for trust roots. Refuses to overwrite existing files.
 *
 * usage: keygen <output-dir> <key-id>
 */
const [outDir, keyId] = process.argv.slice(2);
if (outDir === undefined || keyId === undefined || !/^[A-Za-z0-9._-]{1,64}$/.test(keyId)) {
  process.stderr.write("usage: keygen <output-dir> <key-id>\n");
  process.exitCode = 3;
} else {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  mkdirSync(outDir, { recursive: true });
  const privatePath = join(outDir, `${keyId}.pem`);
  const publicPath = join(outDir, `${keyId}.public.json`);
  writeFileSync(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }).toString(), {
    flag: "wx",
    mode: 0o600,
  });
  const jwk = publicKey.export({ format: "jwk" });
  writeFileSync(
    publicPath,
    JSON.stringify({ keyId, jwk: { kty: "OKP", crv: "Ed25519", x: jwk.x } }, null, 2) + "\n",
    { flag: "wx" },
  );
  process.stdout.write(`wrote ${privatePath} (private, keep secret) and ${publicPath}\n`);
}

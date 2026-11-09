import { KMSClient, GetPublicKeyCommand, SignCommand } from "@aws-sdk/client-kms";
import type { TrustRoot } from "@dip/authority";
import type { SignerInput, SigningProvider } from "@dip/crypto";
import { AwsKmsSigningProvider, type KmsTransport } from "@dip/kms";
import type { SignerSettings } from "./config.js";

/** Refusal to start. The message names the role and key ID, never key material. */
export class SignerError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "SignerError";
  }
}

/** Real AWS KMS transport. Credentials come from the SDK's default chain, never from config. */
export function awsKmsTransport(region: string): KmsTransport {
  const client = new KMSClient({ region });
  return {
    async sign(input) {
      const out = await client.send(
        new SignCommand({
          KeyId: input.KeyId,
          Message: input.Message,
          MessageType: input.MessageType,
          SigningAlgorithm: input.SigningAlgorithm,
        }),
      );
      return { Signature: out.Signature };
    },
    async getPublicKey(input) {
      const out = await client.send(new GetPublicKeyCommand({ KeyId: input.KeyId }));
      return { PublicKey: out.PublicKey };
    },
  };
}

export interface SignerOptions {
  readonly kmsRegion: string | null;
  /** Injectable for tests. Defaults to the AWS transport. */
  readonly kmsTransport?: (region: string) => KmsTransport;
}

/**
 * Resolves one signer. A local key is used as loaded. A KMS key is used only if its
 * public key matches the trust root that the operator pinned in configuration. A
 * mismatch, or a missing or revoked root, refuses to start.
 */
export async function resolveSigner(
  role: string,
  settings: SignerSettings,
  trustRoots: readonly TrustRoot[],
  options: SignerOptions,
): Promise<SignerInput> {
  if (settings.privateKey !== null) {
    return { keyId: settings.keyId, privateKey: settings.privateKey };
  }
  const kmsKeyId = settings.kmsKeyId;
  if (kmsKeyId === null || options.kmsRegion === null) {
    throw new SignerError("KMS_NOT_CONFIGURED", `${role}: a KMS key needs kms.region`);
  }
  const make = options.kmsTransport ?? awsKmsTransport;
  const provider = new AwsKmsSigningProvider(kmsKeyId, make(options.kmsRegion));
  const root = trustRoots.find((r) => r.keyId === settings.keyId);
  if (root === undefined || root.status !== "ACTIVE") {
    throw new SignerError(
      "SIGNER_ROOT_MISSING",
      `${role}: no ACTIVE trust root pinned for ${settings.keyId}`,
    );
  }
  const live = await provider.publicJwk();
  if (live.x !== root.jwk.x) {
    throw new SignerError(
      "SIGNER_KEY_MISMATCH",
      `${role}: the KMS public key does not match the pinned trust root ${settings.keyId}; refusing to start`,
    );
  }
  // The protocol identifies signatures by the pinned trust-root keyId, not the KMS key ID.
  const signing: SigningProvider = {
    keyId: settings.keyId,
    publicJwk: () => provider.publicJwk(),
    sign: (message) => provider.sign(message),
  };
  return signing;
}

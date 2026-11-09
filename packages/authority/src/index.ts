export { PROTOCOL_VERSION } from "./version.js";
export {
  DipError,
  MAX_MINOR_UNITS,
  obj,
  exactKeys,
  id,
  int,
  bool,
  currency,
  time,
  list,
} from "./validate.js";
export { parseAuthorityBody, type AuthorityBody, type DelegationRef } from "./body.js";
export { TrustRootSet, type TrustRoot } from "./trust.js";
export {
  AUTHORITY_DOMAIN,
  REVOCATION_DOMAIN,
  signAuthority,
  signRevocation,
  verifyAuthoritySignature,
  verifyRevocationSignature,
  parseSignedRevocation,
  type RevocationBody,
  type SignatureFault,
  type SignedAuthority,
  type SignedRevocation,
} from "./signing.js";
export { AuthorityRegistry } from "./registry.js";
export type { Journal } from "./journal.js";

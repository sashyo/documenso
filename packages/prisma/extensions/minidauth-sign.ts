/**
 * Cohort threshold signing for Documenso, via the minidauth-seal sidecar.
 *
 * Sealing hides a document; signing proves one. When a recipient completes signing, we ask the Tide
 * ORK cohort - through the sidecar's `/sign` - to threshold-sign a canonical statement about the
 * completion, gated on the signer's quorum-granted role. What comes back is an ordinary VVK signature:
 * 64 bytes of Ed25519 anyone can verify with the vendor public key, over the statement alone. No
 * signing key is ever assembled, in Documenso or the sidecar, so no operator - and no stolen database -
 * can forge a completed signature, and altering the row the statement is rebuilt from breaks it.
 *
 * Off unless MINIDAUTH_SEAL_URL is set. Every call here fails safe (returns null / false) rather than
 * throwing into the signing flow: a signing service being down must never block a person from signing.
 */
import { currentReaderToken } from './minidauth-reader';

const sidecarUrl = (): string | undefined => process.env.MINIDAUTH_SEAL_URL;
const enabled = (): boolean => Boolean(sidecarUrl());

async function sidecar(path: string, body: unknown, bearer?: string): Promise<any> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (bearer) {
    headers['Authorization'] = `Bearer ${bearer}`;
  }
  const r = await fetch(sidecarUrl() + path, { method: 'POST', headers, body: JSON.stringify(body) });
  const text = await r.text();
  if (!r.ok) {
    throw new Error(`minidauth-sign ${path} -> ${r.status} ${text}`);
  }
  return text ? JSON.parse(text) : {};
}

/**
 * The exact statement the cohort signs, rebuilt verbatim to verify. Everything in it is clear (not
 * sealed) so a verifier - this app, an auditor, a court - can reconstruct it from the row and check the
 * signature with only the vendor public key. Order and separators are fixed on purpose.
 */
export function signingStatement(p: {
  envelopeId: string;
  recipientEmail: string;
  itemHash: string;
  signedAt: string;
}): string {
  return `documenso.sign;envelope=${p.envelopeId};signer=${p.recipientEmail};item=${p.itemHash};at=${p.signedAt}`;
}

/**
 * Ask the cohort (through the sidecar) to threshold-sign `statement` as the current reader. Returns the
 * signature (base64), or null when signing is off, there is no reader in context, or the cohort refuses
 * (the signer does not hold the role). Never throws.
 */
export async function cohortSign(statement: string): Promise<string | null> {
  if (!enabled()) {
    return null;
  }
  const readerToken = currentReaderToken();
  if (!readerToken) {
    return null;
  }
  try {
    const { signature } = await sidecar('/sign', { payload: statement }, readerToken);
    return typeof signature === 'string' && signature.length > 0 ? signature : null;
  } catch {
    return null;
  }
}

/** Verify a cohort signature over `statement` against the vendor public key (via the sidecar's public
 *  `/verify`). Anyone can call this; it carries no secret. Returns false on any failure. */
export async function verifyCohortSignature(statement: string, signature: string | null | undefined): Promise<boolean> {
  if (!enabled() || !signature) {
    return false;
  }
  try {
    const { valid } = await sidecar('/verify', { payload: statement, signature });
    return Boolean(valid);
  } catch {
    return false;
  }
}

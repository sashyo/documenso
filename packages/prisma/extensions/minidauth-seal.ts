/**
 * minidauth field sealing for Documenso (Prisma client extension).
 *
 * Seals selected personal fields (a document's title, a recipient's name, the email subject/message
 * sent to signers, a signer's typed or drawn signature, and the text a signer typed into a field)
 * with minidauth before they reach Postgres, and opens them again on the way out. The engine lives in
 * the `minidauth-prisma` package; this file only supplies Documenso's field map and re-exports the
 * same symbols the rest of the app already imports, so nothing else changes.
 *
 * Off by default. Set MINIDAUTH_SEAL_URL to point at the sidecar to turn it on; unset, every path is a
 * no-op and Documenso behaves exactly like upstream. See the package README for how it works, the
 * fail-closed/fail-safe behaviour, and the queryability limit.
 */
import { Prisma } from '@prisma/client';

import { createMinidauthSeal } from 'minidauth-prisma';

// camelCase Prisma model -> the scalar string fields to seal. Left in the clear on purpose:
//   - Recipient.email is an indexed lookup / signing-token key (dedup, routing, auth).
//   - Envelope.token/secondaryId/qrToken are opaque routing keys, not personal data.
const SEALED: Record<string, string[]> = {
  envelope: ['title'],
  recipient: ['name'],
  documentMeta: ['subject', 'message'],
  signature: ['typedSignature', 'signatureImageAsBase64'],
  field: ['customText'],
};

// Relations to descend into, so a nested write (envelope.create with recipients and fields) and an
// included read both reach the child's sealed fields. Directional so descent always terminates.
const RELATIONS: Record<string, Record<string, string>> = {
  envelope: { recipients: 'recipient', fields: 'field', documentMeta: 'documentMeta' },
  recipient: { signatures: 'signature', fields: 'field' },
  field: { signature: 'signature' },
};

const seal = createMinidauthSeal({ Prisma, sealed: SEALED, relations: RELATIONS });

/**
 * Open sealed fields on records that did NOT come through the Prisma client extension. Documenso
 * builds several list/detail reads with Kysely raw SQL, which bypasses the extension, so call this on
 * such results before returning them.
 */
export const openSealedRecords = seal.openSealedRecords;

/**
 * Wrap the Prisma client so the models in SEALED seal on write and open on read. Append it last in the
 * `.$extends(...)` chain so it is the outermost layer.
 */
export function minidauthSealExtension() {
  return seal.extension;
}

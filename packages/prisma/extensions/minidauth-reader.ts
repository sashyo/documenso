/**
 * Per-user reader identity for minidauth field opening.
 *
 * The engine lives in the `minidauth-prisma` package; this file only re-exports the same symbols the
 * app already imports. A request handler wraps its work in `withMinidauthReader(userId, fn)` (see
 * trpc/server/trpc.ts), and the seal extension opens sealed fields as that user, gated by minidauth's
 * quorum grant. No reader in context means the field stays sealed. `minidauth-sign.ts` also reads the
 * current reader token from here.
 */
export { withMinidauthReader, currentReaderToken, mintReaderToken } from 'minidauth-prisma';

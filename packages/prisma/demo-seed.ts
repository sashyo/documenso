import fs from 'node:fs';
import path from 'node:path';

import { incrementDocumentId } from '@documenso/lib/server-only/envelope/increment-id';
import { SignatureLevel } from '@documenso/lib/types/signature-level';
import { prefixedId } from '@documenso/lib/universal/id';
import { DocumentDataType, DocumentSource, EnvelopeType } from './client';
import { prisma } from './index';

// A few realistic documents for the existing example user (id 3), so the dashboard has meaningful
// sealed data to open. Each write seals the title, the recipient name, and the email subject/message.
const USER_ID = 3;
const TEAM_ID = 3;
const DOCS = [
  {
    title: 'Mutual NDA',
    name: 'Jordan Rivera',
    email: 'jordan.rivera@northwind.example',
    subject: 'Please sign: Mutual NDA',
    message: 'Hi Jordan, please review and sign our mutual NDA.',
  },
  {
    title: 'Series A SAFE',
    name: 'Priya Anand',
    email: 'priya@brightseed.example',
    subject: 'Series A SAFE for signature',
    message: 'Priya, the SAFE is ready for your signature.',
  },
  {
    title: 'Employment Agreement',
    name: 'Marcus Lindqvist',
    email: 'marcus.l@parallel.example',
    subject: 'Your employment agreement',
    message: 'Welcome aboard - please sign your offer letter.',
  },
  {
    title: 'Consulting Agreement',
    name: 'Aisha Bello',
    email: 'aisha.bello@consult.example',
    subject: 'Consulting agreement',
    message: 'Aisha, here is the consulting agreement for review.',
  },
  {
    title: 'Master Services Agreement',
    name: 'Chen Wei',
    email: 'chen.wei@vendor.example',
    subject: 'MSA for countersignature',
    message: 'Please countersign the attached MSA.',
  },
];

async function main() {
  const examplePdf = fs.readFileSync(path.join(__dirname, '../../assets/example.pdf')).toString('base64');

  for (const d of DOCS) {
    const documentData = await prisma.documentData.create({
      data: { type: DocumentDataType.BYTES_64, data: examplePdf, initialData: examplePdf },
    });
    const documentId = await incrementDocumentId();
    const documentMeta = await prisma.documentMeta.create({
      data: { subject: d.subject, message: d.message },
    });

    const env = await prisma.envelope.create({
      data: {
        id: prefixedId('envelope'),
        secondaryId: documentId.formattedDocumentId,
        internalVersion: 1,
        signatureLevel: SignatureLevel.SES,
        type: EnvelopeType.DOCUMENT,
        documentMetaId: documentMeta.id,
        source: DocumentSource.DOCUMENT,
        title: d.title,
        envelopeItems: {
          create: { id: prefixedId('envelope_item'), title: d.title, documentDataId: documentData.id, order: 1 },
        },
        userId: USER_ID,
        teamId: TEAM_ID,
        recipients: {
          create: { name: d.name, email: d.email, token: Math.random().toString(36).slice(2, 9) },
        },
      },
    });
    // env.title comes back sealed here (a seed script has no reader identity); the app opens it.
    console.log('created envelope for:', d.title);
  }
  console.log('demo-seed done');
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

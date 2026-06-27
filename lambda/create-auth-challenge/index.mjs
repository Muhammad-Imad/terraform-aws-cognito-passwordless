// Create Auth Challenge trigger.
//
// Generates the one-time secret for a sign-in attempt, persists it in the
// challenge store with a short TTL, and delivers it to the user over the
// configured channel:
//
//   * delivery_mode = "code"       -> numeric OTP via SES (email) and/or SNS (SMS).
//   * delivery_mode = "magic_link" -> an HMAC-signed click-through link via SES.
//
// The plaintext code is NEVER returned to the client. Only a public, non-secret
// hint (e.g. the masked destination) is placed in publicChallengeParameters.
// The answer the user supplies is checked later by the verify trigger.

import { randomInt, createHmac } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";

const REGION = process.env.AWS_REGION;
const STORE = process.env.CHALLENGE_STORE ?? "dynamodb";
const DELIVERY_MODE = process.env.DELIVERY_MODE ?? "code";
const CODE_LENGTH = Number.parseInt(process.env.CODE_LENGTH ?? "6", 10);
const CODE_TTL_SECONDS = Number.parseInt(process.env.CODE_TTL_SECONDS ?? "180", 10);
const EMAIL_ENABLED = process.env.EMAIL_ENABLED === "true";
const SMS_ENABLED = process.env.SMS_ENABLED === "true";
const SES_FROM_ADDRESS = process.env.SES_FROM_ADDRESS;
const MAGIC_LINK_BASE_URL = process.env.MAGIC_LINK_BASE_URL;
const SECRET_ARN = process.env.SECRET_ARN;

// Clients are created once per container so subsequent invocations reuse them.
const ddb = STORE === "dynamodb"
  ? DynamoDBDocumentClient.from(new DynamoDBClient({ region: REGION }))
  : null;
const ses = EMAIL_ENABLED ? new SESv2Client({ region: REGION }) : null;
const sns = SMS_ENABLED ? new SNSClient({ region: REGION }) : null;
const secrets = SECRET_ARN ? new SecretsManagerClient({ region: REGION }) : null;

// Cache the signing key across invocations; secret rotation re-creates the
// execution environment, so this stays correct without per-call fetches.
let cachedSigningKey = null;

async function getSigningKey() {
  if (cachedSigningKey) return cachedSigningKey;
  const out = await secrets.send(new GetSecretValueCommand({ SecretId: SECRET_ARN }));
  const parsed = JSON.parse(out.SecretString);
  cachedSigningKey = parsed.magicLinkSigningKey;
  if (!cachedSigningKey) {
    throw new Error("Secret is missing required key: magicLinkSigningKey");
  }
  return cachedSigningKey;
}

/** Cryptographically uniform numeric code of CODE_LENGTH digits. */
function generateCode() {
  let code = "";
  for (let i = 0; i < CODE_LENGTH; i += 1) {
    code += randomInt(0, 10).toString();
  }
  return code;
}

/** Stable, opaque id derived from the Cognito sub + the round number. */
function challengeId(event) {
  const sub = event.request.userAttributes.sub ?? event.userName;
  const round = (event.request.session ?? []).length;
  return `${event.userPoolId}#${sub}#${round}`;
}

async function storeChallenge(id, secret) {
  const expiresAt = Math.floor(Date.now() / 1000) + CODE_TTL_SECONDS;

  if (STORE === "dynamodb") {
    await ddb.send(
      new PutCommand({
        TableName: process.env.DDB_TABLE_NAME,
        Item: { challengeId: id, secret, attempts: 0, expiresAt },
      }),
    );
    return;
  }

  // Redis path. Imported lazily so the (much larger) client is not loaded into
  // memory for the DynamoDB default.
  const { createClient } = await import("redis");
  const [host, port] = process.env.REDIS_ENDPOINT.split(":");
  const client = createClient({
    socket: { host, port: Number(port), tls: true },
  });
  await client.connect();
  try {
    await client.set(`challenge:${id}`, JSON.stringify({ secret, attempts: 0 }), {
      EX: CODE_TTL_SECONDS,
    });
  } finally {
    await client.quit();
  }
}

function maskEmail(email) {
  const [local, domain] = email.split("@");
  const head = local.slice(0, 1);
  return `${head}${"*".repeat(Math.max(local.length - 1, 1))}@${domain}`;
}

function buildMagicLink(id, code, signingKey) {
  // The link carries the challenge id + an HMAC over "id.code" so the verify
  // trigger can confirm authenticity without a server-side lookup of the link
  // itself. The code is still validated against the store for replay safety.
  const payload = `${id}.${code}`;
  const sig = createHmac("sha256", signingKey).update(payload).digest("base64url");
  const token = Buffer.from(`${payload}.${sig}`).toString("base64url");
  const sep = MAGIC_LINK_BASE_URL.includes("?") ? "&" : "?";
  return `${MAGIC_LINK_BASE_URL}${sep}token=${token}`;
}

async function sendEmail(toAddress, code, link) {
  const subject = DELIVERY_MODE === "magic_link" ? "Your sign-in link" : "Your sign-in code";
  const body =
    DELIVERY_MODE === "magic_link"
      ? `Click to sign in: ${link}\n\nThis link expires in ${CODE_TTL_SECONDS} seconds.`
      : `Your verification code is ${code}.\n\nIt expires in ${CODE_TTL_SECONDS} seconds.`;

  await ses.send(
    new SendEmailCommand({
      FromEmailAddress: SES_FROM_ADDRESS,
      Destination: { ToAddresses: [toAddress] },
      Content: {
        Simple: {
          Subject: { Data: subject },
          Body: { Text: { Data: body } },
        },
      },
    }),
  );
}

async function sendSms(phoneNumber, code) {
  await sns.send(
    new PublishCommand({
      PhoneNumber: phoneNumber,
      Message: `Your verification code is ${code}. Expires in ${CODE_TTL_SECONDS}s.`,
      MessageAttributes: {
        "AWS.SNS.SMS.SMSType": { DataType: "String", StringValue: "Transactional" },
      },
    }),
  );
}

/**
 * @param {import("aws-lambda").CreateAuthChallengeTriggerEvent} event
 */
export const handler = async (event) => {
  // Only act on the first custom challenge in a session; re-presentations reuse
  // the already-delivered code so users are not spammed on a retry.
  const session = event.request.session ?? [];
  const isFirst = session.length === 0 || session[session.length - 1].challengeName !== "CUSTOM_CHALLENGE";

  const id = challengeId(event);
  const email = event.request.userAttributes.email;
  const phone = event.request.userAttributes.phone_number;

  let publicHint = {};

  if (isFirst) {
    const code = generateCode();
    await storeChallenge(id, code);

    const deliveries = [];
    if (EMAIL_ENABLED && email) {
      const link = DELIVERY_MODE === "magic_link" ? buildMagicLink(id, code, await getSigningKey()) : null;
      deliveries.push(sendEmail(email, code, link));
      publicHint.destination = maskEmail(email);
      publicHint.channel = "email";
    }
    if (SMS_ENABLED && phone) {
      deliveries.push(sendSms(phone, code));
      publicHint.channel = publicHint.channel ? "email+sms" : "sms";
    }

    await Promise.all(deliveries);
  } else {
    publicHint.channel = "resend";
  }

  // Public parameters are visible to the (unauthenticated) client — never put
  // the code here. The verify trigger receives the code via privateChallenge.
  event.response.publicChallengeParameters = {
    challengeId: id,
    deliveryMode: DELIVERY_MODE,
    ...publicHint,
  };

  // privateChallengeParameters are passed only to the verify trigger by Cognito.
  event.response.privateChallengeParameters = { challengeId: id };

  // Surfaced to the client UI (e.g. to show "code sent to a***@example.com").
  event.response.challengeMetadata = "PASSWORDLESS_CHALLENGE";

  return event;
};

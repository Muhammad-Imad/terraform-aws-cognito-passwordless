// Verify Auth Challenge Response trigger.
//
// This is the security-critical handler and the only one that reads the stored
// secret. It runs VPC-isolated on private, multi-AZ subnets. Responsibilities:
//
//   1. Look up the stored challenge by id.
//   2. Reject if missing/expired (covers TTL eviction and replay).
//   3. Compare the supplied answer to the stored secret in CONSTANT TIME.
//   4. Track attempts; a correct answer deletes the challenge so it cannot be
//      replayed. Define-Auth-Challenge enforces the overall attempt ceiling.
//
// For magic links, the client submits the signed token; we re-derive the HMAC
// with the Secrets Manager key, confirm it, then still validate the embedded
// code against the store so a leaked-but-expired link cannot be reused.

import { timingSafeEqual, createHmac } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  DeleteCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";

const REGION = process.env.AWS_REGION;
const STORE = process.env.CHALLENGE_STORE ?? "dynamodb";
const DELIVERY_MODE = process.env.DELIVERY_MODE ?? "code";
const MAX_ATTEMPTS = Number.parseInt(process.env.MAX_ATTEMPTS ?? "3", 10);
const SECRET_ARN = process.env.SECRET_ARN;

const ddb = STORE === "dynamodb"
  ? DynamoDBDocumentClient.from(new DynamoDBClient({ region: REGION }))
  : null;
const secrets = SECRET_ARN ? new SecretsManagerClient({ region: REGION }) : null;

let cachedSigningKey = null;

async function getSigningKey() {
  if (cachedSigningKey) return cachedSigningKey;
  const out = await secrets.send(new GetSecretValueCommand({ SecretId: SECRET_ARN }));
  cachedSigningKey = JSON.parse(out.SecretString).magicLinkSigningKey;
  if (!cachedSigningKey) throw new Error("Secret is missing required key: magicLinkSigningKey");
  return cachedSigningKey;
}

/** Length-safe constant-time string comparison. */
function constantTimeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  // timingSafeEqual throws on length mismatch; pad to equal length first while
  // still recording the mismatch so unequal-length inputs always fail.
  if (bufA.length !== bufB.length) {
    // Compare against itself to burn a comparable amount of time, then fail.
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

/** Read the stored challenge record. Returns null when absent/expired. */
async function readChallenge(id) {
  if (STORE === "dynamodb") {
    const out = await ddb.send(
      new GetCommand({ TableName: process.env.DDB_TABLE_NAME, Key: { challengeId: id } }),
    );
    if (!out.Item) return null;
    // Defend against the race window where TTL has lapsed but DynamoDB has not
    // yet physically evicted the item.
    if (out.Item.expiresAt && out.Item.expiresAt < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return { secret: out.Item.secret, attempts: out.Item.attempts ?? 0 };
  }

  const { createClient } = await import("redis");
  const [host, port] = process.env.REDIS_ENDPOINT.split(":");
  const client = createClient({ socket: { host, port: Number(port), tls: true } });
  await client.connect();
  try {
    const raw = await client.get(`challenge:${id}`);
    return raw ? JSON.parse(raw) : null;
  } finally {
    await client.quit();
  }
}

async function consumeChallenge(id) {
  if (STORE === "dynamodb") {
    await ddb.send(
      new DeleteCommand({ TableName: process.env.DDB_TABLE_NAME, Key: { challengeId: id } }),
    );
    return;
  }
  const { createClient } = await import("redis");
  const [host, port] = process.env.REDIS_ENDPOINT.split(":");
  const client = createClient({ socket: { host, port: Number(port), tls: true } });
  await client.connect();
  try {
    await client.del(`challenge:${id}`);
  } finally {
    await client.quit();
  }
}

async function recordFailedAttempt(id, currentAttempts) {
  if (STORE === "dynamodb") {
    await ddb.send(
      new UpdateCommand({
        TableName: process.env.DDB_TABLE_NAME,
        Key: { challengeId: id },
        UpdateExpression: "SET attempts = if_not_exists(attempts, :z) + :one",
        ExpressionAttributeValues: { ":z": 0, ":one": 1 },
      }),
    );
    return;
  }
  const { createClient } = await import("redis");
  const [host, port] = process.env.REDIS_ENDPOINT.split(":");
  const client = createClient({ socket: { host, port: Number(port), tls: true } });
  await client.connect();
  try {
    const raw = await client.get(`challenge:${id}`);
    if (raw) {
      const rec = JSON.parse(raw);
      rec.attempts = (rec.attempts ?? currentAttempts) + 1;
      // Preserve the remaining TTL rather than resetting it.
      const ttl = await client.ttl(`challenge:${id}`);
      await client.set(`challenge:${id}`, JSON.stringify(rec), { EX: ttl > 0 ? ttl : 1 });
    }
  } finally {
    await client.quit();
  }
}

/**
 * For magic links the submitted answer is a base64url token of "id.code.sig".
 * Returns the embedded code if the signature is valid, otherwise null.
 */
async function extractCodeFromToken(token, expectedId) {
  let decoded;
  try {
    decoded = Buffer.from(token, "base64url").toString("utf8");
  } catch {
    return null;
  }
  const lastDot = decoded.lastIndexOf(".");
  if (lastDot < 0) return null;
  const payload = decoded.slice(0, lastDot);
  const sig = decoded.slice(lastDot + 1);

  const expectedSig = createHmac("sha256", await getSigningKey()).update(payload).digest("base64url");
  if (!constantTimeEqual(sig, expectedSig)) return null;

  const [id, code] = payload.split(".");
  if (id !== expectedId) return null;
  return code;
}

/**
 * @param {import("aws-lambda").VerifyAuthChallengeResponseTriggerEvent} event
 */
export const handler = async (event) => {
  const id = event.request.privateChallengeParameters?.challengeId;
  const answer = event.request.challengeAnswer ?? "";

  event.response.answerCorrect = false;

  if (!id) return event;

  const record = await readChallenge(id);
  if (!record) {
    // Expired, never created, or already consumed — fail closed.
    return event;
  }

  if ((record.attempts ?? 0) >= MAX_ATTEMPTS) {
    await consumeChallenge(id);
    return event;
  }

  // Resolve the value we actually compare against the stored secret.
  let submitted = answer;
  if (DELIVERY_MODE === "magic_link") {
    const code = await extractCodeFromToken(answer, id);
    if (code === null) {
      await recordFailedAttempt(id, record.attempts ?? 0);
      return event;
    }
    submitted = code;
  }

  if (constantTimeEqual(submitted, record.secret)) {
    event.response.answerCorrect = true;
    // One-time use: destroy the challenge so the same code/link cannot replay.
    await consumeChallenge(id);
  } else {
    await recordFailedAttempt(id, record.attempts ?? 0);
  }

  return event;
};

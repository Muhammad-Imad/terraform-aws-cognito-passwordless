// Define Auth Challenge trigger.
//
// Cognito calls this handler at every step of a CUSTOM_AUTH session to decide
// what happens next. It is pure control logic: no network, no store, no
// secrets — which is why it runs on the smallest possible role and outside any
// VPC. It drives a simple state machine:
//
//   1. Brand new session            -> issue a CUSTOM_CHALLENGE.
//   2. Previous CUSTOM_CHALLENGE OK  -> issue tokens (success).
//   3. Previous CUSTOM_CHALLENGE bad -> re-issue, until MAX_ATTEMPTS is hit.
//   4. Attempts exhausted            -> fail the authentication.

const MAX_ATTEMPTS = Number.parseInt(process.env.MAX_ATTEMPTS ?? "3", 10);

/**
 * @param {import("aws-lambda").DefineAuthChallengeTriggerEvent} event
 */
export const handler = async (event) => {
  const session = event.request.session ?? [];

  // No challenges presented yet — this is the first round trip.
  if (session.length === 0) {
    event.response.issueTokens = false;
    event.response.failAuthentication = false;
    event.response.challengeName = "CUSTOM_CHALLENGE";
    return event;
  }

  const last = session[session.length - 1];

  // The most recent custom challenge succeeded -> grant tokens.
  if (last.challengeName === "CUSTOM_CHALLENGE" && last.challengeResult === true) {
    event.response.issueTokens = true;
    event.response.failAuthentication = false;
    return event;
  }

  // Count how many custom challenges the user has already failed.
  const failed = session.filter(
    (c) => c.challengeName === "CUSTOM_CHALLENGE" && c.challengeResult === false,
  ).length;

  if (failed >= MAX_ATTEMPTS) {
    // Lock the session. The client must restart the auth flow from scratch.
    event.response.issueTokens = false;
    event.response.failAuthentication = true;
    return event;
  }

  // Wrong answer but attempts remain — present another challenge.
  event.response.issueTokens = false;
  event.response.failAuthentication = false;
  event.response.challengeName = "CUSTOM_CHALLENGE";
  return event;
};

const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const app = express();

// Append logs to a local file for easier debugging
const logStream = fs.createWriteStream("webhook-log.txt", { flags: "a" });
function log(message) {
  const timestamp = new Date().toISOString();
  const line = `[${timestamp}] ${message}`;
  console.log(line);
  logStream.write(`${line}\n`);
}

// Capture raw body for signature verification
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const APP_SECRET = process.env.APP_SECRET;

app.get("/webhook", (req, res) => {
  log("GET /webhook - verification check");
  log(`Query params: ${JSON.stringify(req.query)}`);
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  // Meta verification request
  if (mode === "subscribe") {
    if (!VERIFY_TOKEN) {
      log("VERIFY_TOKEN not set; cannot verify webhook.");
      return res.sendStatus(500);
    }
    if (token === VERIFY_TOKEN) {
      log("Verification success");
      return res.status(200).send(challenge);
    }
    log("Verification failed: token mismatch");
    return res.sendStatus(403);
  }

  // Any other GET (like manual browser checks)
  return res.status(200).send("OK");
});

app.post("/webhook", (req, res) => {
  log("POST /webhook - event received");
  log(`Headers: ${JSON.stringify(req.headers)}`);
  log(`Body: ${JSON.stringify(req.body, null, 2)}`);

  res.sendStatus(200);
  // Meta requires quick 200 OK
  const signature = req.get("x-hub-signature-256");
  if (APP_SECRET && signature && signature.startsWith("sha256=")) {
    const expected = `sha256=${crypto
      .createHmac("sha256", APP_SECRET)
      .update(req.rawBody || Buffer.from(""))
      .digest("hex")}`;

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      log("Signature mismatch (dev mode). Still acked 200.");
      return;
    }
    log("Signature verified");
  } else {
    log("No signature verification (dev mode).");
  }

  if (req.body && req.body.entry) {
    req.body.entry.forEach((entry) => {
      entry.changes?.forEach((change) => {
        log(`Change field: ${change.field}`);
        log(`Change value: ${JSON.stringify(change.value, null, 2)}`);
      });
    });
  }
});

app.get("/", (_, res) => res.send("OK"));

const port = process.env.PORT || 4040;
app.listen(port, () => {
  log(`Listening on port ${port}`);
  log(`VERIFY_TOKEN set: ${Boolean(VERIFY_TOKEN)}`);
  log(`APP_SECRET set: ${Boolean(APP_SECRET)}`);
});

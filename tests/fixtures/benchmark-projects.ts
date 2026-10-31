import fs from "node:fs/promises";
import path from "node:path";

// Synthetic fixture projects for measuring local rule detection.
// Every value is fake. Token-shaped strings are assembled at runtime so the
// repository itself never contains a literal that looks like a real credential.

export interface ExpectedFinding {
  file: string;
  line: number;
  ruleId: string;
}

export interface FixtureProject {
  name: string;
  kind: "vulnerable" | "clean";
  files: Record<string, Array<[string, string[]]>>;
}

const fakeAwsKeyId = "AKIA" + "IOSFODNN7EXAMPLE";
const fakePrivateKeyHeader = "-----BEGIN " + "PRIVATE KEY-----";
const fakePrivateKeyFooter = "-----END " + "PRIVATE KEY-----";
const fakeStripeKey = "sk_" + "live_" + "FIXTUREFIXTUREFIXTURE0000";
const fakeSlackToken = "xox" + "b-0000000000-0000000000-FIXTUREFIXTURE";
const fakeGoogleKey = "AI" + "za" + "SyFIXTURE_FIXTURE_FIXTURE_FIXTURE00";

const SECRET = ["secret.detected"];
const CODE_AND_SECRET = ["code.hardcoded-secret", "secret.detected"];

export const fixtureProjects: FixtureProject[] = [
  {
    name: "vuln-node",
    kind: "vulnerable",
    files: {
      "src/server.js": [
        ['const express = require("express");', []],
        ['const cors = require("cors");', []],
        ['const multer = require("multer");', []],
        ['const { exec } = require("child_process");', []],
        ['const jwt = require("jsonwebtoken");', []],
        ['const fs = require("fs");', []],
        ["const app = express();", []],
        ["app.use(cors());", ["code.unsafe-cors"]],
        ['const STRIPE_SECRET_KEY = "fixture-stripe-secret-value-0000";', CODE_AND_SECRET],
        ['const apiKey = "fixture-api-key-value-1234";', CODE_AND_SECRET],
        ['app.get("/admin/users", (req, res) => res.json(listUsers()));', ["code.missing-authorization"]],
        ['app.get("/users/:id", (req, res) => {', ["code.missing-authorization"]],
        ["  db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);", ["code.raw-sql"]],
        ["});", []],
        ['app.post("/run", (req, res) => exec("convert " + req.body.file));', ["code.shell-execution"]],
        ["app.post(\"/calc\", (req, res) => res.send(String(eval(req.body.expr))));", ["code.eval-usage"]],
        ['app.get("/proxy", async (req, res) => res.send(await fetch(req.query.url)));', ["code.ssrf-user-controlled-url"]],
        ['app.get("/file", (req, res) => res.send(fs.readFileSync(req.query.name, "utf8")));', ["code.path-traversal"]],
        ['app.get("/download", (req, res) => res.sendFile(req.params.path));', ["code.path-traversal"]],
        ["app.get(\"/me\", (req, res) => res.json(jwt.decode(req.headers.authorization)));", ["code.weak-jwt"]],
        ['app.post("/login", (req, res) => console.log("login attempt", req.body.password));', ["code.dangerous-logging"]],
        ['const upload = multer({ dest: "public/uploads" });', ["code.unsafe-upload"]],
        ['app.post("/avatar", upload.single("avatar"), (req, res) => res.sendStatus(204));', ["code.unsafe-upload"]],
        ["app.listen(3000);", []]
      ],
      "src/auth.js": [
        ['const jwt = require("jsonwebtoken");', []],
        ["function check(token, key) {", []],
        ["  return jwt.verify(token, key, { ignoreExpiration: true });", ["code.weak-jwt"]],
        ["}", []],
        ["function insecure(token) {", []],
        ['  return jwt.verify(token, null, { algorithms: ["none"] });', ["code.weak-jwt"]],
        ["}", []],
        ["module.exports = { check, insecure };", []]
      ],
      "src/cors-config.js": [
        ['module.exports = { origin: "*", credentials: true };', ["code.unsafe-cors"]],
        ['function allowAll(res) { res.setHeader("Access-Control-Allow-Origin", "*"); }', ["code.unsafe-cors"]]
      ],
      "src/page.jsx": [
        ["export function Bio({ html }) {", []],
        ["  return <div dangerouslySetInnerHTML={{ __html: html }} />;", ["code.next-dangerous-html"]],
        ["}", []]
      ],
      "src/payments.js": [
        [`const stripe = require("stripe")("${fakeStripeKey}");`, SECRET],
        [`const slack = new WebClient("${fakeSlackToken}");`, SECRET],
        [`const maps = loadMaps({ key: "${fakeGoogleKey}" });`, SECRET]
      ],
      ".env": [
        ["OPENAI_API_KEY=fixture-openai-key-value-5678", SECRET],
        ["DATABASE_PASSWORD=fixture-db-password-9012", SECRET],
        ["PORT=3000", []]
      ],
      ".npmrc": [
        ["//registry.npmjs.org/:_authToken=fixture-npm-token-7890", SECRET]
      ],
      "config/settings.json": [
        ["{", []],
        ['  "client_secret": "fixture-client-secret-3456"', CODE_AND_SECRET],
        ["}", []]
      ],
      "config/credentials.ini": [
        ["[default]", []],
        [`aws_access_key_id = ${fakeAwsKeyId}`, SECRET]
      ],
      "keys/server.pem": [
        [fakePrivateKeyHeader, SECRET],
        ["FIXTUREFIXTUREFIXTUREFIXTURE", []],
        [fakePrivateKeyFooter, []]
      ],
      "src/passphrase.ts": [
        ['export const config = { password: "fixture horse battery staple" };', CODE_AND_SECRET]
      ]
    }
  },
  {
    name: "clean-node",
    kind: "clean",
    files: {
      "src/server.js": [
        ['const express = require("express");', []],
        ['const cors = require("cors");', []],
        ['const fs = require("fs");', []],
        ['const path = require("path");', []],
        ['const jwt = require("jsonwebtoken");', []],
        ['const { execFile } = require("child_process");', []],
        ["const app = express();", []],
        ['app.use(cors({ origin: ["https://app.example.test"], credentials: true }));', []],
        ["const apiKey = process.env.API_KEY;", []],
        ["function requireAuth(req, res, next) { return req.user ? next() : res.sendStatus(401); }", []],
        ['app.get("/admin/users", requireAuth, (req, res) => res.json([]));', []],
        ['app.get("/users/:id", requireAuth, async (req, res) => {', []],
        ["  const token = req.headers.authorization;", []],
        ["  const password = req.body.password;", []],
        ['  const user = await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);', []],
        ["  const match = /^(\\d+)$/.exec(req.params.id);", []],
        ["  const doc = await Model.findById(req.params.id).exec();", []],
        ['  console.log("Token refreshed for user", user.id);', []],
        ['  res.json(jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] }));', []],
        ["});", []],
        ['app.post("/thumb", requireAuth, (req, res) => execFile("convert", ["in.png", "out.png"]));', []],
        ['app.post("/notify", requireAuth, async (req, res) => {', []],
        ['  await fetch("https://hooks.example.test/notify", { method: "POST", body: JSON.stringify(req.body) });', []],
        ["  res.sendStatus(204);", []],
        ["});", []],
        ['fs.readFile(path.join(__dirname, "template.html"), "utf8", (err, body) => {});', []],
        ["app.listen(3000);", []]
      ],
      "src/page.jsx": [
        ['import DOMPurify from "dompurify";', []],
        ["export const Bio = ({ html }) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;", []],
        ["export const fetchItems = (q) => fetch(`/api/items?query=${encodeURIComponent(q)}`);", []]
      ],
      ".env.example": [
        ["OPENAI_API_KEY=", []],
        ["DATABASE_PASSWORD=${DATABASE_PASSWORD}", []],
        ["STRIPE_SECRET_KEY=your-stripe-secret-key-here", []],
        ["PORT=3000", []]
      ],
      "config/settings.json": [
        ["{", []],
        ['  "passwordMinLength": 12,', []],
        ['  "tokenTtlSeconds": 3600', []],
        ["}", []]
      ]
    }
  },
  {
    name: "vuln-python",
    kind: "vulnerable",
    files: {
      "app.py": [
        ["import os, subprocess, requests", []],
        ["from fastapi import FastAPI, Request", []],
        ["app = FastAPI(debug=True)", ["code.fastapi-debug"]],
        ['SECRET_KEY = "fixture-django-secret-0000"', CODE_AND_SECRET],
        ["def run(cmd):", []],
        ["    subprocess.run(cmd, shell=True)", ["code.shell-execution"]],
        ['    os.system("ls " + cmd)', ["code.shell-execution"]],
        ["def lookup(cursor, user_id):", []],
        ['    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")', ["code.raw-sql"]],
        ['    cursor.execute("SELECT * FROM users WHERE name = %s" % user_id)', ["code.raw-sql"]],
        ['    cursor.execute("DELETE FROM users WHERE id = {}".format(user_id))', ["code.raw-sql"]],
        ["def proxy(request: Request):", []],
        ['    return requests.get(request.query_params["url"]).text', ["code.ssrf-user-controlled-url"]],
        ["def read(request):", []],
        ['    return open(request.args["path"]).read()', ["code.path-traversal"]]
      ]
    }
  },
  {
    name: "clean-python",
    kind: "clean",
    files: {
      "app.py": [
        ["import logging, os, subprocess", []],
        ["from fastapi import FastAPI", []],
        ["app = FastAPI()", []],
        ['SECRET_KEY = os.environ["SECRET_KEY"]', []],
        ["logger = logging.getLogger(__name__)", []],
        ["def lookup(cursor, user_id):", []],
        ['    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))', []],
        ['    logger.info(f"Deleted user {user_id}")', []],
        ["def run():", []],
        ['    subprocess.run(["ls", "-l"], check=True)', []],
        ["def infer(model, batch):", []],
        ["    model.eval()", []],
        ["    return model(batch)", []],
        ["def update_status(user_id):", []],
        ['    print(f"Could not update profile for {user_id}")', []],
        ["    token = request_token()", []]
      ]
    }
  },
  {
    name: "vuln-java",
    kind: "vulnerable",
    files: {
      "src/SecurityConfig.java": [
        ["class SecurityConfig {", []],
        ["  void a(HttpSecurity http) { http.csrf().disable(); }", ["code.spring-csrf-disabled"]],
        ["  void b(HttpSecurity http) { http.csrf(AbstractHttpConfigurer::disable); }", ["code.spring-csrf-disabled"]],
        ['  @CrossOrigin(origins = "*")', ["code.unsafe-cors"]],
        ["  void c(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); }", ["code.shell-execution"]],
        ['  String password = "fixture-java-password";', CODE_AND_SECRET],
        ["}", []]
      ]
    }
  },
  {
    name: "clean-java",
    kind: "clean",
    files: {
      "src/SecurityConfig.java": [
        ["class SecurityConfig {", []],
        ["  void a(HttpSecurity http) { http.csrf(Customizer.withDefaults()); }", []],
        ['  @CrossOrigin(origins = "https://app.example.test")', []],
        ["  String password = System.getenv(\"APP_PASSWORD\");", []],
        ["}", []]
      ]
    }
  }
];

export async function materializeFixture(project: FixtureProject, root: string): Promise<ExpectedFinding[]> {
  const expected: ExpectedFinding[] = [];
  for (const [file, lines] of Object.entries(project.files)) {
    const fullPath = path.join(root, file);
    await fs.mkdir(path.dirname(fullPath), { recursive: true });
    await fs.writeFile(fullPath, lines.map(([text]) => text).join("\n") + "\n", "utf8");
    lines.forEach(([, rules], index) => {
      for (const ruleId of rules) {
        expected.push({ file, line: index + 1, ruleId });
      }
    });
  }
  return expected;
}

/**
 * Fixture corpus for the credential detectors.
 *
 * Every credential in this file is fabricated and non-functional: none of the
 * values authenticates against any service or protects any resource. The
 * values that look like vendor documentation samples are the vendors' own
 * published placeholders, reproduced so the detectors can be tested for
 * suppressing them.
 */

export interface SecretFixture {
  readonly label: string
  readonly kind: string
  readonly tier: "A" | "B"
  readonly value: string
  readonly context: string
}

export interface BenignFixture {
  readonly label: string
  readonly reason: string
  readonly text: string
}

const PEM_BLOCK = `-----BEGIN RSA PRIVATE KEY-----
571USmkzsuopKmRqTB80Y8brYBRfXsfL7G3ilDZpD/HhmGX1yylqFjExcQoWv34l
vnvNgaFL24tDMSW57XUJRTXTh8xtPauibN2uy36zkSBWT6zzQ69HJkhpLopkQqdw
x+RmSiSP484H4Ie1dmRCSqUmaUntchpN6rHKMd+uacp91aQ23IfMhwOroTbyugOq
YMiFQz2RGEaNhsO6YoE67LMdTHAdch0w81BkUuS0p/qB7RTv0BYm2YT0bt4ZCrcO
-----END RSA PRIVATE KEY-----`

// Truncated private keys: output cut off before the END marker. Bodies are
// random base64, not key material.
const PEM_TRUNCATED_OPENSSH = [
  "-----BEGIN OPENSSH PRIVATE KEY-----",
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
  "Q4XkR2vLm9TqW3zPb7NcY1hJ5fD8sGx0aEuKiOp4rBtZ6wMn2lVjU+yHdA/gCeF3oQ7iSN",
  "xP5mRk1Tz9WqLv3Hc8Yb2Nf6Ju4Dg0Ks7Ea1Ri5Mo9Ux3Vp2Gt6Bw8Ql4Zn0Hy7Cj1Ie5",
].join("\n")

const PEM_TRUNCATED_ENCRYPTED = [
  "-----BEGIN RSA PRIVATE KEY-----",
  "Proc-Type: 4,ENCRYPTED",
  "DEK-Info: AES-128-CBC,3F2A9C1E7B04D2A6F8E1C3B5A7D9E0F2",
  "",
  "kV7tR2mQ9xL4wZ8pB3nJ6hY1cF5dS0gK7aE2uI9oP4rT6yW3qM8vN1bX5zC0jH7lG2sD",
  "Tq4Wm8Rz2Xk6Vn0Pb5Lc9Hd3Jf7Gs1Ya5Ue9Io3Kt7Ow1Mp5Qr9Sx3Zv7Cn1Bh5Dj9Fl",
].join("\n")

/** As stored inside a JSON string: the newlines are the two characters "\\n". */
const PEM_TRUNCATED_JSON_ESCAPED = [
  "-----BEGIN PRIVATE KEY-----",
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDm4Xk9TqW3zPb7NcY1",
  "hJ5fD8sGx0aEuKiOp4rBtZ6wMn2lVjU",
].join("\\n")

const CERT_BODY = `Ib/NHRAr9XxkEhA/SfudB/B2pbASsRYerEATXmmWoeLhWfsbGByNN0glddIkHcNk
hhutOd9KXqXobCh/VpA2DW6FCwbbSbPF+/DR94ujMO5YrbQxBCPG6NmXW7ek1nZJ
kAzxgfcZryzTwCFHquUNgOmyDslhTQUR5GEeWv/coT2riufaYtT2kS3mngQHsQsf
ji5YMeKXbGdnTqy2syt6MYGUGmET2MAKQBzH7eGOrFwyL9vdvE2AQGK6hFWhmdvi
+C+7zwYIN4Gj0kTunu7RlTQHd+OyBUPZWK1Gbw9eS4JJ2ji0bNPScXj6VM7C73QO
Boo+65nIDYj0OzTbbVZsGwXfQHdtu7O656JPvxJ/fZ+glj1LIyCThoescpY0h4V2
4OfRzfi7otoGh+lcm0xswJXbo3MPc/argtc258qISmrJaLcV7vD6rnhNt7h98yhx`

const MINIFIED_BUNDLE = `!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?t(exports):"function"==typeof define&&define.amd?define(["exports"],t):t((e="undefined"!=typeof globalThis?globalThis:e||self).redactor={})}(this,function(e){"use strict";var t=function(e,n){return e===n},n=function(e,n){return e+n},r=function(e,n,r){return Math.min(Math.max(e,n),r)},o=function(e){return e.reduce(n,0)},i=Object.prototype.hasOwnProperty,a=Array.isArray,s=function(e,n){return Object.assign({},e,n)},u=[],c={},l=function(e){return typeof e},f=function(){return u.slice()},d=function(e,n){var r=arguments.length>2&&void 0!==arguments[2]?arguments[2]:null;return null===r?t(e,n):s(e,{value:r})};var ah=function(e,zj){var t=e.parse(zj);return d(t,"GY0Z5N05fcLQAaXM")};var lu=function(e,hu){var t=e.scan(hu);return d(t,"CAUE8HCv29UfCE6e")};var y9=function(e,rg){var t=e.match(rg);return d(t,"cWf1gI6kA/YmrLHx")};var jr=function(e,vx){var t=e.emit(vx);return d(t,"govCSPfVzIV+ufMR")};var i9=function(e,dh){var t=e.wrap(dh);return d(t,"LI1pckBT5QX8KiNL")};var hc=function(e,ih){var t=e.slice(ih);return d(t,"sgESoj0BkPUjXeIt")};var gq=function(e,mi){var t=e.index(mi);return d(t,"2sNqomkRehO7rPL1")};var zs=function(e,co){var t=e.reduce(co);return d(t,"8+Hh1I5fSZ7fZ/wc")};var cd=function(e,qb){var t=e.filter(qb);return d(t,"yE+U1VeGanHalzWd")};var nh=function(e,ez){var t=e.assign(ez);return d(t,"IE47wOGKxLzbszgu")};var qf=function(e,on){var t=e.clone(on);return d(t,"NI1ARi70hFkss2IG")};var tg=function(e,cc){var t=e.merge(cc);return d(t,"cqto2cCeLfLu2+GS")};var yh=function(e,cz){var t=e.split(cz);return d(t,"vhTGTDF/U4hNmCSN")};var ea=function(e,li){var t=e.join(li);return d(t,"fgF/0ZfRzpKOfY+I")};var mt=function(e,nm){var t=e.trim(nm);return d(t,"5h6jyHDB0xYHAAZL")};var qx=function(e,pv){var t=e.lower(pv);return d(t,"B0znKo1cUeC+aKrL")};var bs=function(e,th){var t=e.upper(th);return d(t,"9yc/FxPcmmQQ95sR")};var y6=function(e,nf){var t=e.focus(nf);return d(t,"feC7LIOa+ybQCrjc")};var cw=function(e,us){var t=e.blur(us);return d(t,"QbTDE8i6CbofHKsT")};var tz=function(e,di){var t=e.mount(di);return d(t,"jkn1fADK6Ubhlm8L")};var k2=function(e,qb){var t=e.parse(qb);return d(t,"YeZclpRKxXr3ACwu")};var k1=function(e,dh){var t=e.scan(dh);return d(t,"v8H+k5I7LHqnIahC")};var ce=function(e,ga){var t=e.match(ga);return d(t,"lWDGFLj7u0sFCxk4")};var ox=function(e,dy){var t=e.emit(dy);return d(t,"hSlFHYaJmhDijxIO")};var lo=function(e,hr){var t=e.wrap(hr);return d(t,"jL9T4T0oicLkO6k8")};var jp=function(e,vm){var t=e.slice(vm);return d(t,"c79SbPrDFQB+FSf1")};var h=function(e){return"function"==typeof e},p=function(e,n){for(var r in n)i.call(n,r)&&(e[r]=n[r]);return e},m={name:"redactor",version:"0.2.1",render:function(e){var n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{};return s({id:e,className:"rdr-cell Ojffgzq9",style:n},f())}};e.assert=h,e.clone=s,e.events=u,e.registry=c,e.index=o,e.version="0.2.1",e.default=m,Object.defineProperty(e,"__esModule",{value:!0})});`

export const SECRETS: readonly SecretFixture[] = [
  {
    label: "aws-access-key-id-env",
    kind: "aws-access-key-id",
    tier: "A",
    value: "AKIAV3XKQ7DEMOQ4WXYZ",
    context: `# .env.production
AWS_REGION=eu-central-1
AWS_ACCESS_KEY_ID=AKIAV3XKQ7DEMOQ4WXYZ
AWS_DEFAULT_OUTPUT=json`,
  },
  {
    label: "aws-secret-access-key-yaml",
    kind: "aws-secret-access-key",
    tier: "A",
    value: "kR9tQ2xPz8LmWn4YbVcDfGhJkNpQsUvXwZaB3E5H",
    context: `# config/aws.yml
aws:
  region: eu-central-1
  aws_secret_access_key: "kR9tQ2xPz8LmWn4YbVcDfGhJkNpQsUvXwZaB3E5H"`,
  },
  {
    label: "github-pat-classic",
    kind: "github-pat",
    tier: "A",
    value: "ghp_F4KEF4KEF4KEF4KEF4KEF4KEF4KEF4KEF4KE",
    context: `# .env.local
GITHUB_TOKEN=ghp_F4KEF4KEF4KEF4KEF4KEF4KEF4KEF4KEF4KE
GITHUB_REPOSITORY=opencode-labs/redactor`,
  },
  {
    label: "github-pat-oauth",
    kind: "github-pat",
    tier: "A",
    value: "gho_EXAMPLE0EXAMPLE0EXAMPLE0EXAMPLE0EXAM",
    context: `const octokit = new Octokit({ auth: "gho_EXAMPLE0EXAMPLE0EXAMPLE0EXAMPLE0EXAM" })`,
  },
  {
    label: "github-pat-user",
    kind: "github-pat",
    tier: "A",
    value: "ghu_DEMOTOKENDEMOTOKENDEMOTOKENDEMOTOKEN",
    context: `{
  "githubApp": {
    "installationId": 4815162342,
    "userToken": "ghu_DEMOTOKENDEMOTOKENDEMOTOKENDEMOTOKEN"
  }
}`,
  },
  {
    label: "github-pat-server",
    kind: "github-pat",
    tier: "A",
    value: "ghs_TESTONLYTESTONLYTESTONLYTESTONLYTEST",
    context: `- uses: actions/checkout@v4
  with:
    token: ghs_TESTONLYTESTONLYTESTONLYTESTONLYTEST`,
  },
  {
    label: "github-pat-refresh",
    kind: "github-pat",
    tier: "A",
    value: "ghr_SAMPLEVALSAMPLEVALSAMPLEVALSAMPLEVAL",
    context: `git remote add origin https://ghr_SAMPLEVALSAMPLEVALSAMPLEVALSAMPLEVAL@github.com/opencode-labs/redactor.git`,
  },
  {
    label: "slack-bot-token-source",
    kind: "slack-token",
    tier: "A",
    value: "xoxb-123456789012-345678901234-FAKEFAKEFAKEFAKEFAKE1234",
    context: `export const slack = new WebClient("xoxb-123456789012-345678901234-FAKEFAKEFAKEFAKEFAKE1234")`,
  },
  {
    label: "slack-user-token-yaml",
    kind: "slack-token",
    tier: "A",
    value: "xoxp-123456789012-234567890123-345678901234-00001111222233334444555566667777",
    context: `notifications:
  slack:
    user_token: xoxp-123456789012-234567890123-345678901234-00001111222233334444555566667777`,
  },
  {
    label: "stripe-live-key-env",
    kind: "stripe-live-key",
    tier: "A",
    value: "sk_live_51F4kEExAmPlE0000000000000000",
    context: `# .env.production
STRIPE_SECRET_KEY=sk_live_51F4kEExAmPlE0000000000000000
STRIPE_WEBHOOK_TOLERANCE=300`,
  },
  {
    label: "stripe-test-key-env",
    kind: "stripe-test-key",
    tier: "B",
    value: "sk_test_51Q3mZx8TnVw2RbYpLdFgHjKsQ4mXzCnBvWrTyU",
    context: `# .env.staging
STRIPE_TEST_KEY=sk_test_51Q3mZx8TnVw2RbYpLdFgHjKsQ4mXzCnBvWrTyU`,
  },
  {
    label: "google-api-key-json",
    kind: "google-api-key",
    tier: "A",
    value: "AIzaSyDFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
    context: `{
  "projectId": "redactor-staging",
  "maps": {
    "apiKey": "AIzaSyDFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
  }
}`,
  },
  {
    label: "openai-api-key-env",
    kind: "openai-api-key",
    tier: "A",
    value: "sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
    context: `OPENAI_API_KEY=sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
OPENAI_ORG_ID=org-fake000000000000000000`,
  },
  {
    label: "anthropic-api-key-source",
    kind: "anthropic-api-key",
    tier: "A",
    value:
      "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
    context: `const anthropic = new Anthropic({
  apiKey: "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
})`,
  },
  {
    label: "gitlab-pat-ci",
    kind: "gitlab-pat",
    tier: "A",
    value: "glpat-FAKEFAKEFAKE00000000",
    context: `variables:
  GITLAB_TOKEN: glpat-FAKEFAKEFAKE00000000
  GITLAB_HOST: gitlab.example.com`,
  },
  {
    label: "npm-token-npmrc",
    kind: "npm-token",
    tier: "A",
    value: "npm_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
    context: `//registry.npmjs.org/:_authToken=npm_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
always-auth=true`,
  },
  {
    label: "sendgrid-api-key-source",
    kind: "sendgrid-api-key",
    tier: "A",
    value: "SG.FAKEKEYFAKEKEYFAKEKEY1.FAKESECRETFAKESECRETFAKESECRETFAKESECRETFAK",
    context: `sgMail.setApiKey("SG.FAKEKEYFAKEKEYFAKEKEY1.FAKESECRETFAKESECRETFAKESECRETFAKESECRETFAK")`,
  },
  {
    label: "twilio-api-key-source",
    kind: "twilio-api-key",
    tier: "A",
    value: "SK00001111222233334444555566667777",
    context: `const client = twilio(process.env.TWILIO_ACCOUNT_SID, "SK00001111222233334444555566667777")`,
  },
  {
    label: "pem-rsa-private-key",
    kind: "pem-private-key",
    tier: "A",
    value: PEM_BLOCK,
    context: `The vault handoff writes the deploy key before the rollout:

${PEM_BLOCK}

The runner reloads it on the next tick and never writes it to disk.`,
  },
  {
    label: "pem-truncated-by-head",
    kind: "pem-private-key",
    tier: "A",
    value: PEM_TRUNCATED_OPENSSH,
    context: `$ head -4 ~/.ssh/deploy_ed25519
${PEM_TRUNCATED_OPENSSH}`,
  },
  {
    label: "pem-truncated-before-tool-note",
    kind: "pem-private-key",
    tier: "A",
    value: PEM_TRUNCATED_ENCRYPTED,
    context: `${PEM_TRUNCATED_ENCRYPTED}

... output truncated (24 more lines). Full output saved to /tmp/out-3f2a.txt`,
  },
  {
    label: "pem-truncated-json-escaped",
    kind: "pem-private-key",
    tier: "A",
    value: PEM_TRUNCATED_JSON_ESCAPED,
    context: `{
  "type": "service_account",
  "private_key_id": "placeholder",
  "private_key": "${PEM_TRUNCATED_JSON_ESCAPED}`,
  },
  {
    label: "jwt-bearer-log-line",
    kind: "jwt",
    tier: "A",
    value:
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyX2Zha2VfMk42eVVjUSIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSIsImF1ZCI6ImFwaS5leGFtcGxlLmNvbSIsImlhdCI6MTczMDAwMDAwMCwiZXhwIjoxNzYxNTM2MDAwLCJzY29wZSI6InJlYWQ6Y29uZmlnIn0.KMvwt_xCEeyMcR7v06y5sFkR7hYZyNWOURvkFghPyPg",
    context: `2026-03-14T09:31:02.114Z INFO  http.request method=GET path=/v2/profile status=200 authorization="Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyX2Zha2VfMk42eVVjUSIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSIsImF1ZCI6ImFwaS5leGFtcGxlLmNvbSIsImlhdCI6MTczMDAwMDAwMCwiZXhwIjoxNzYxNTM2MDAwLCJzY29wZSI6InJlYWQ6Y29uZmlnIn0.KMvwt_xCEeyMcR7v06y5sFkR7hYZyNWOURvkFghPyPg"`,
  },
  {
    label: "postgres-connection-string",
    kind: "connection-string-password",
    tier: "A",
    value: "S3cretFakeP4ss",
    context: `const pool = new Pool({ connectionString: "postgres://app_user:S3cretFakeP4ss@db.staging.example.com:5432/payments" })`,
  },
  {
    label: "generic-api-key-prose",
    kind: "generic-secret",
    tier: "B",
    value: "kQ3mZx8TnVw2RbYpLdFgHjKsQ4mXzCnBvWrTyUiOpAsDfGhJ",
    context: `The deploy bot posted its config dump to the incident channel:

api_key = "kQ3mZx8TnVw2RbYpLdFgHjKsQ4mXzCnBvWrTyUiOpAsDfGhJ"
token_ttl = 3600

Reverting that line unblocked the rollout.`,
  },
  {
    label: "json-quoted-key",
    kind: "generic-secret",
    tier: "B",
    value: "Vq7Lm2Xc9Rt4Wz8Pk3Nb6Hy1",
    context: `// appsettings.Production.json
{
  "Logging": { "LogLevel": { "Default": "Warning" } },
  "Database": {
    "Host": "db.internal",
    "Password": "Vq7Lm2Xc9Rt4Wz8Pk3Nb6Hy1"
  }
}`,
  },
  {
    label: "python-dict-quoted-key",
    kind: "generic-secret",
    tier: "B",
    value: "Tz4Kp9Wm2Qx7Rv3Ld8Nc5Bh6",
    context: `CLIENT_CONFIG = {'base_url': 'https://api.example.com', 'api_key': 'Tz4Kp9Wm2Qx7Rv3Ld8Nc5Bh6'}`,
  },
  {
    label: "go-short-variable-declaration",
    kind: "generic-secret",
    tier: "B",
    value: "Jm8Rx3Vt6Lq1Wp9Zk4Nd7Cb2",
    context: `func client() *http.Client {
	apiToken := "Jm8Rx3Vt6Lq1Wp9Zk4Nd7Cb2"
	return newClient(apiToken)
}`,
  },
  {
    label: "ruby-hash-rocket",
    kind: "generic-secret",
    tier: "B",
    value: "Hx5Np2Rk8Vm3Tq9Lw6Zc1Bd4",
    context: `Stripe.configure(:webhook_secret => "Hx5Np2Rk8Vm3Tq9Lw6Zc1Bd4", :timeout => 30)`,
  },
  {
    label: "env-password-with-punctuation",
    kind: "generic-secret",
    tier: "B",
    value: "Xk9#mQ2!vL8pR4@tW7zB.n3J",
    context: `# .env.local
DB_HOST=localhost
DB_PASSWORD=Xk9#mQ2!vL8pR4@tW7zB.n3J
DB_POOL=10`,
  },
  {
    label: "env-password-symbol-early",
    kind: "generic-secret",
    tier: "B",
    value: "P@ssw0rd-Rk7vT2mX9qL4wZ",
    context: `export SMTP_PASSWORD=P@ssw0rd-Rk7vT2mX9qL4wZ`,
  },
  {
    label: "connection-string-at-in-password",
    kind: "connection-string-password",
    tier: "A",
    value: "Fk3@pR9!vZ",
    context: `MYSQL_URL=mysql://svc_orders:Fk3@pR9!vZ@mysql.internal:3306/orders`,
  },
  {
    label: "authorization-bearer-opaque",
    kind: "authorization-header",
    tier: "B",
    value: "Wq8Zt3Lk6Xm1Rv9Pn4Bc7Hd2Jf5",
    context: `curl -sS -H "Authorization: Bearer Wq8Zt3Lk6Xm1Rv9Pn4Bc7Hd2Jf5" https://api.example.com/v1/me`,
  },
  {
    label: "authorization-basic-header",
    kind: "authorization-header",
    tier: "B",
    value: "c3ZjX2RlcGxveTpUcjdLcTJYbTlWbjQ=",
    context: `> GET /artifacts/latest HTTP/1.1
> Host: nexus.internal
> Authorization: Basic c3ZjX2RlcGxveTpUcjdLcTJYbTlWbjQ=
> Accept: */*`,
  },
  {
    label: "netrc-password",
    kind: "netrc-password",
    tier: "A",
    value: "hunter2deploy",
    context: `$ cat ~/.netrc
machine api.heroku.com
  login deploy@example.com
  password hunter2deploy`,
  },
  {
    label: "github-fine-grained-pat-env",
    kind: "github-fine-grained-pat",
    tier: "A",
    value: "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",
    context: `# .env.local
GITHUB_TOKEN=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
GITHUB_OWNER=opencode-labs`,
  },
  {
    label: "gitlab-pipeline-trigger-token",
    kind: "gitlab-pat",
    tier: "A",
    value: "glptt-acP6YQsRAhIabUOiYEfVGariMVtO",
    context: `variables:
  GITLAB_PIPELINE_TOKEN: glptt-acP6YQsRAhIabUOiYEfVGariMVtO
  GITLAB_HOST: gitlab.example.com`,
  },
  {
    label: "slack-refresh-token-xoxr",
    kind: "slack-token",
    tier: "A",
    value: "xoxr-924281139949-456874089749-yutcuoummazeoyhlzmxtkbsf",
    context: `$ grep token .env
SLACK_REFRESH_TOKEN=xoxr-924281139949-456874089749-yutcuoummazeoyhlzmxtkbsf`,
  },
  {
    label: "slack-app-token-config",
    kind: "slack-app-token",
    tier: "A",
    value: "xapp-1-7V12B22B35-0098320841-xpdxc6w436py7g1cyy07dwr4wvwfq37hth7qx4vl",
    context: `{
  "slack": {
    "appToken": "xapp-1-7V12B22B35-0098320841-xpdxc6w436py7g1cyy07dwr4wvwfq37hth7qx4vl",
    "socketMode": true
  }
}`,
  },
  {
    label: "slack-incoming-webhook-url",
    kind: "slack-webhook",
    tier: "A",
    value: "https://hooks.slack.com/services/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",
    context: `# .env.production
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/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
SLACK_CHANNEL=#deploys`,
  },
  {
    label: "discord-webhook-curl",
    kind: "discord-webhook",
    tier: "A",
    value: "https://discord.com/api/webhooks/8528664580973078069/ujQc4uUci__VkxgBgPy9nf5fxyZGuZrdXl9ih5LxVVHRVSX-dUmiuS-waojhnB27",
    context: `curl -sS -X POST https://discord.com/api/webhooks/8528664580973078069/ujQc4uUci__VkxgBgPy9nf5fxyZGuZrdXl9ih5LxVVHRVSX-dUmiuS-waojhnB27 -d @release.json`,
  },
  {
    label: "telegram-bot-token-env",
    kind: "telegram-bot-token",
    tier: "A",
    value: "0525789193:AA1BuqF_Gq42g0kkcDI3o5Yz262BJheEVDh",
    context: `# .env.production
TELEGRAM_BOT_TOKEN=0525789193:AA1BuqF_Gq42g0kkcDI3o5Yz262BJheEVDh
TELEGRAM_CHAT_ID=-1001234567890`,
  },
  {
    label: "huggingface-token-env",
    kind: "huggingface-token",
    tier: "A",
    value: "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",
    context: `# .env.local
HUGGING_FACE_HUB_TOKEN=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
HF_HOME=/home/dev/.cache/huggingface`,
  },
  {
    label: "groq-api-key-env",
    kind: "groq-api-key",
    tier: "A",
    value: "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",
    context: `# .env.local
GROQ_API_KEY=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`,
  },
  {
    label: "replicate-api-token-env",
    kind: "replicate-api-token",
    tier: "A",
    value: "r8_p9sD1gy7DlWOu80Aia6nDHEzjOmnLRugDag1I",
    context: `# .env.local
REPLICATE_API_TOKEN=r8_p9sD1gy7DlWOu80Aia6nDHEzjOmnLRugDag1I`,
  },
  {
    label: "xai-api-key-env",
    kind: "xai-api-key",
    tier: "A",
    value: "xai-Tq7kt4KBBLcSCnDEX8SHXasBjb6o79zfuJ51EtP3JmQavSb7UfQgmmhkYzLes902YmFXk3Sxe5DnllSF",
    context: `# .env.local
XAI_API_KEY=xai-Tq7kt4KBBLcSCnDEX8SHXasBjb6o79zfuJ51EtP3JmQavSb7UfQgmmhkYzLes902YmFXk3Sxe5DnllSF`,
  },
  {
    label: "perplexity-api-key-env",
    kind: "perplexity-api-key",
    tier: "A",
    value: "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",
    context: `# .env.local
PPLX_API_KEY=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`,
  },
  {
    label: "openrouter-api-key-env",
    kind: "openrouter-api-key",
    tier: "A",
    value: "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",
    context: `# .env.local
OPENROUTER_API_KEY=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`,
  },
  {
    label: "stripe-webhook-secret-env",
    kind: "stripe-webhook-secret",
    tier: "A",
    value: "whsec_pDyrcPG7wyAmmAArHHOY1eonkv4lLTfAwjM3TunR",
    context: `# .env.production
STRIPE_WEBHOOK_SECRET=whsec_pDyrcPG7wyAmmAArHHOY1eonkv4lLTfAwjM3TunR
STRIPE_WEBHOOK_TOLERANCE=300`,
  },
  {
    label: "azure-storage-account-key-connection-string",
    kind: "azure-storage-account-key",
    tier: "A",
    value: "Sw2c65dBqyzFRezQ1qvw5wfRjjvm2/JeKKkoHCY+cOm7CeXB0WAlHLM+n1vJWA3BR8iYfsUYJ7n0hZRDX4vy+J==",
    context: `AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=redactorstore;AccountKey=Sw2c65dBqyzFRezQ1qvw5wfRjjvm2/JeKKkoHCY+cOm7CeXB0WAlHLM+n1vJWA3BR8iYfsUYJ7n0hZRDX4vy+J==;EndpointSuffix=core.windows.net`,
  },
  {
    label: "azure-ad-client-secret-env",
    kind: "azure-ad-client-secret",
    tier: "A",
    value: "RPT1Q~wnff0lJkd6QEwXXhzUD4l1VT~c6t79vWP",
    context: `# .env.production
AZURE_CLIENT_ID=8f2b1c4d-0000-1111-2222-333344445555
AZURE_CLIENT_SECRET=RPT1Q~wnff0lJkd6QEwXXhzUD4l1VT~c6t79vWP
AZURE_TENANT_ID=44445555-6666-7777-8888-999900001111`,
  },
  {
    label: "azure-blob-sas-signature",
    kind: "azure-sas-signature",
    tier: "A",
    value: "S%ub5B9DSr6=Li/FfIrNcVFX20tJ2r04T0AUSRKWkhcpfFXD",
    context: `https://redactorstore.blob.core.windows.net/exports/2026-03.csv?sv=2023-11-03&ss=b&srt=sco&sig=S%ub5B9DSr6=Li/FfIrNcVFX20tJ2r04T0AUSRKWkhcpfFXD`,
  },
  {
    label: "digitalocean-token-env",
    kind: "digitalocean-token",
    tier: "A",
    value: "dop_v1_65bfe27ee57f045aac299dc9b75cf49ba8a487c7a13fef339e8a199337ef401c",
    context: `# .env.production
DIGITALOCEAN_TOKEN=dop_v1_65bfe27ee57f045aac299dc9b75cf49ba8a487c7a13fef339e8a199337ef401c
DIGITALOCEAN_REGION=fra1`,
  },
  {
    label: "vault-service-token-shell",
    kind: "vault-token",
    tier: "A",
    value: "hvs.IEyzFCaGlUZi63CiefEAHmGUrQo07DyPxnq2cgZLqZSTd8Gvf4rREDnmPy3dncdKAC4fjVNkvspalI9FiYznuYuaGCKGUGLL",
    context: `$ export VAULT_TOKEN=hvs.IEyzFCaGlUZi63CiefEAHmGUrQo07DyPxnq2cgZLqZSTd8Gvf4rREDnmPy3dncdKAC4fjVNkvspalI9FiYznuYuaGCKGUGLL
$ vault kv get secret/payments`,
  },
  {
    label: "terraform-cloud-token-env",
    kind: "terraform-cloud-token",
    tier: "A",
    value: "ceA61GPVijUAwi.atlasv1.CAEIRRO8rK3MOPETFxyuaHjyGF9V6cwSeWNijCUBeYDyvIVcOfZ-cxBi_Zt-9Fp8-",
    context: `# .env.production
TFC_TOKEN=ceA61GPVijUAwi.atlasv1.CAEIRRO8rK3MOPETFxyuaHjyGF9V6cwSeWNijCUBeYDyvIVcOfZ-cxBi_Zt-9Fp8-
TF_CLOUD_ORGANIZATION=opencode-labs`,
  },
  {
    label: "databricks-token-env",
    kind: "databricks-token",
    tier: "A",
    value: "dapi1d5da364431b70806d37303d77757397-2",
    context: `# .env.production
DATABRICKS_TOKEN=dapi1d5da364431b70806d37303d77757397-2
DATABRICKS_HOST=https://dbc.example.cloud.databricks.com`,
  },
  {
    label: "shopify-access-token-env",
    kind: "shopify-token",
    tier: "A",
    value: "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",
    context: `# .env.production
SHOPIFY_ACCESS_TOKEN=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
SHOPIFY_STORE=redactor-labs.myshopify.com`,
  },
  {
    label: "pypi-token-pypirc",
    kind: "pypi-token",
    tier: "A",
    value: "pypi-AgEIcHlwaS5vcmclXbICm2B41LbfzcXF-5Ao4LKcIa69G5XE7yAcBqW5DkCcIHrmpXhiX",
    context: `# ~/.pypirc
[distutils]
index-servers = pypi

[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmclXbICm2B41LbfzcXF-5Ao4LKcIa69G5XE7yAcBqW5DkCcIHrmpXhiX`,
  },
  {
    label: "dockerhub-pat-config",
    kind: "dockerhub-pat",
    tier: "A",
    value: "dckr_pat_Tq9C-h7uzuljaHTHfBI5Qel_6UOxxa",
    context: `{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "dckr_pat_Tq9C-h7uzuljaHTHfBI5Qel_6UOxxa"
    }
  }
}`,
  },
  {
    label: "postman-api-key-env",
    kind: "postman-api-key",
    tier: "A",
    value: "PMAK-ffd2d8e1e38eb6434477bd06-9e01580fb30710718cb4e4f87e5956c867",
    context: `# .env.local
POSTMAN_API_KEY=PMAK-ffd2d8e1e38eb6434477bd06-9e01580fb30710718cb4e4f87e5956c867`,
  },
  {
    label: "linear-api-key-env",
    kind: "linear-api-key",
    tier: "A",
    value: "lin_api_EvYdwyASg7HiKVbhHE4G6s0Zhm7HDxI9KWmw2zDd",
    context: `# .env.local
LINEAR_API_KEY=lin_api_EvYdwyASg7HiKVbhHE4G6s0Zhm7HDxI9KWmw2zDd`,
  },
  {
    label: "atlassian-api-token-env",
    kind: "atlassian-api-token",
    tier: "A",
    value: "ATATT3SqI4_I7JmDodj52yoLljKHDukgANoYPEyjCQwPanb-JIwIffUfXxl5SIHczMVisU0C7MkmHjIvPSujkS94BA17y6L1DKTJwywEX7_gSzjC6Tf-jgXb22lxyrvH7bEdgVcP5Y1AHn0eJCCfMuMRMkjQeuQS8eAO=zcvP4Oeuq5zLJyTO9FdeahHRC",
    context: `# .env.production
ATLASSIAN_EMAIL=deploy@example.com
ATLASSIAN_API_TOKEN=ATATT3SqI4_I7JmDodj52yoLljKHDukgANoYPEyjCQwPanb-JIwIffUfXxl5SIHczMVisU0C7MkmHjIvPSujkS94BA17y6L1DKTJwywEX7_gSzjC6Tf-jgXb22lxyrvH7bEdgVcP5Y1AHn0eJCCfMuMRMkjQeuQS8eAO=zcvP4Oeuq5zLJyTO9FdeahHRC`,
  },
  {
    label: "grafana-service-account-token-env",
    kind: "grafana-token",
    tier: "A",
    value: "glsa_M4qCv12p7610pq5dbYsC2Olxn8tXskHp_5647a135",
    context: `# .env.production
GRAFANA_SERVICE_ACCOUNT_TOKEN=glsa_M4qCv12p7610pq5dbYsC2Olxn8tXskHp_5647a135`,
  },
  {
    label: "grafana-cloud-api-key-env",
    kind: "grafana-token",
    tier: "A",
    value: "glc_ZDQ0huZ+300Xr+higErCEfHXjH4Dhlm94GYL==",
    context: `# .env.production
GF_SECURITY_ADMIN_API_KEY=glc_ZDQ0huZ+300Xr+higErCEfHXjH4Dhlm94GYL==`,
  },
  {
    label: "sentry-auth-token-env",
    kind: "sentry-token",
    tier: "A",
    value: "sntrys_aDtLQElXGHRYxCnu_sIMXS2_EkN-JEkEw1LvVcbw1TbT",
    context: `# .env.production
SENTRY_AUTH_TOKEN=sntrys_aDtLQElXGHRYxCnu_sIMXS2_EkN-JEkEw1LvVcbw1TbT
SENTRY_ORG=opencode-labs`,
  },
  {
    label: "supabase-access-token-env",
    kind: "supabase-token",
    tier: "A",
    value: "sbp_d80969766cbd78272c7a64b7591e4a10d6d206e3",
    context: `# .env.local
SUPABASE_ACCESS_TOKEN=sbp_d80969766cbd78272c7a64b7591e4a10d6d206e3
SUPABASE_PROJECT_REF=abcdefghijklmnopqrst`,
  },
  {
    label: "supabase-service-role-key-env",
    kind: "supabase-token",
    tier: "A",
    value: "sb_secret_gwqF8Emw2AfL020Z2VoFHjTomGHYqVAHzq",
    context: `# .env.production
SUPABASE_SERVICE_ROLE_KEY=sb_secret_gwqF8Emw2AfL020Z2VoFHjTomGHYqVAHzq`,
  },
  {
    label: "newrelic-api-key-env",
    kind: "newrelic-api-key",
    tier: "A",
    value: "NRAK-4IMUO1FXUML8IBDHAAOC5VH8CDD",
    context: `# .env.production
NEW_RELIC_USER_API_KEY=NRAK-4IMUO1FXUML8IBDHAAOC5VH8CDD
NEW_RELIC_ACCOUNT_ID=1234567`,
  },
  {
    label: "square-access-token-env",
    kind: "square-token",
    tier: "A",
    value: "sq0atp-0mjwSy1XMFoZojeGNMvl4G",
    context: `# .env.production
SQUARE_ACCESS_TOKEN=sq0atp-0mjwSy1XMFoZojeGNMvl4G
SQUARE_ENVIRONMENT=production`,
  },
  {
    label: "square-client-secret-env",
    kind: "square-token",
    tier: "A",
    value: "sq0csp-P48f_uJtTSqPkY7qzXeaSyFyg3Geoat0c8U9RVlaHLc",
    context: `# .env.production
SQUARE_CLIENT_SECRET=sq0csp-P48f_uJtTSqPkY7qzXeaSyFyg3Geoat0c8U9RVlaHLc`,
  },
  {
    label: "age-secret-key-file",
    kind: "age-secret-key",
    tier: "A",
    value: "AGE-SECRET-KEY-1L2MXK6D066X08N53TW0LYU5U32ZQ4JV3D0PEUGG858C8MPTY9W8S7R2Y0U",
    context: `# keys/backup.agekey
# created 2026-03-14, rotate quarterly
AGE-SECRET-KEY-1L2MXK6D066X08N53TW0LYU5U32ZQ4JV3D0PEUGG858C8MPTY9W8S7R2Y0U`,
  },
  {
    label: "firebase-fcm-server-key-json",
    kind: "firebase-fcm-server-key",
    tier: "A",
    value: "AAAA2Cr8Ym3:APA91bXecz7lc1lEKy6JSz6j5W_ekiFjvvB7nlV0ASbW9AeCGED-HPKwVz_xfWaN9opmsnH9EghAtS19PgQrQ5DTMqZJNyXraG_JPW2_m7cyivxchA4Iyg65b9ioq3",
    context: `{
  "project_info": { "project_id": "redactor-labs" },
  "client": [
    {
      "client_info": { "mobilesdk_app_id": "1:1234567890:android:abcdef0123456789" },
      "api_key": [{ "current_key": "AAAA2Cr8Ym3:APA91bXecz7lc1lEKy6JSz6j5W_ekiFjvvB7nlV0ASbW9AeCGED-HPKwVz_xfWaN9opmsnH9EghAtS19PgQrQ5DTMqZJNyXraG_JPW2_m7cyivxchA4Iyg65b9ioq3" }]
    }
  ]
}`,
  },
  {
    // A base64 PKCS#8 key body without BEGIN/END framing. The certificate deny
    // entry would swallow it if it matched every MII-prefixed run, so this is
    // the fixture that pins the private-key carve-out in that entry.
    label: "pkcs8-private-key-unfenced",
    kind: "generic-secret",
    tier: "B",
    value: "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC78Drfd7b1HGAb9aaXbLe5+CZg8VdHYq2kmnCypKQo",
    context: `# .env.local
private_key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC78Drfd7b1HGAb9aaXbLe5+CZg8VdHYq2kmnCypKQo"`,
  },
]

export const BENIGN: readonly BenignFixture[] = [
  {
    label: "twilio-account-sid-env",
    reason:
      "A Twilio Account SID is a semi-public account identifier that appears in webhook URLs, support tickets and config. It authenticates nothing on its own; the SK auth token does. Redacting it would fire on ordinary Twilio usage while protecting nothing.",
    text: `TWILIO_ACCOUNT_SID=AC11112222333344445555666677778888
TWILIO_SENDER=+15550100`,
  },
  {
    label: "aws-doc-example-keypair",
    reason:
      "AWS's own published example pair. The access key id matches the AKIA anchor outright and the secret sits next to an aws_secret_access_key name, so only an exact-value allowlist checked before every tier keeps these out of the findings.",
    text: `AWS IAM User Guide, the example access keys printed in every SDK README:

aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
  },
  {
    label: "stripe-published-placeholder",
    reason:
      "Vendor-published placeholder from Stripe's docs. Suppress by exact value rather than by the sk_test_ prefix, because the secret corpus separately expects random sk_test_ values to be caught.",
    text: "Stripe's API reference uses sk_test_4eC39HqLyjWDarjtT1zdp7dc as a placeholder in its curl examples; copy it into integration tests, never into production.",
  },
  {
    label: "uuid-v4-prose",
    reason:
      "UUID v4: 36 chars of hex and hyphens with fixed version and variant nibbles. No credential format uses that grouping, and the digit runs are too short for any digest rule.",
    text: "The failed deploy was traced to f47ac10b-58cc-4372-a567-0e02b2c3d479, the request id the incident bot stamped into its report.",
  },
  {
    label: "uuid-v1-prose",
    reason:
      "UUID v1: version nibble 1 and a MAC-derived tail. Same identifier shape as v4; nothing here is a value to fingerprint.",
    text: "Rows from the legacy exporter carry a time-based id such as 2f1b7c2e-5a4d-11ee-8c99-0242ac120002 in the trace column.",
  },
  {
    label: "uuid-v4-code",
    reason:
      "A UUID v4 literal in source. The 8-4-4-4-12 grouping must not match a provider pattern and must not clear a credential threshold.",
    text: `export function withTraceId(handler: Handler): Handler {
  return (req, res) => {
    const traceId = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    return handler(req, res, { traceId })
  }
}`,
  },
  {
    label: "uuid-v1-code",
    reason:
      "A UUID v1 literal in source; a time-based identifier stored in a variable, not a credential literal.",
    text: `const legacyRequestId = "2f1b7c2e-5a4d-11ee-8c99-0242ac120002"
client.setHeader("x-request-id", legacyRequestId)`,
  },
  {
    label: "git-sha-standalone",
    reason:
      "40 lowercase hex chars, the same length as an AWS secret access key. Hex-only plus the absence of an aws_secret_access_key-style anchor is what must keep it out of the findings.",
    text: `export const BUILD_SHA = "8ec3b1f4d2a6c9e0b5f7a1d3c8e2b4f6a0d9c7e5"
export const BUILD_BRANCH = "main"`,
  },
  {
    label: "git-log-output",
    reason:
      "Commit hashes in git-log output. Identical shape to the standalone case, now inside a transcript; length and alphabet alone must never be the trigger.",
    text: `$ git log --oneline -4
8ec3b1f4d2a6c9e0b5f7a1d3c8e2b4f6a0d9c7e5 refactor: extract detector registry
f11d9a0b3c5e7f9a1b2c3d4e5f60718293a4b5c6 fix: handle empty input
3c2d1e0f4a5b6c7d8e9f0a1b2c3d4e5f60718293 chore: bump dev deps
a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f70819 docs: describe tier model`,
  },
  {
    label: "sha256-checksum-lockfile",
    reason:
      "SHA-256 checksum in a Cargo.lock: 64 lowercase hex chars. Integrity digests are content hashes, so hex-only tokens of digest length must be rejected as credentials even when their entropy looks suspicious.",
    text: `[[package]]
name = "redactor-core"
version = "0.2.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"`,
  },
  {
    label: "bcrypt-hash-fixtures-file",
    reason:
      "bcrypt digest. The $2a$10$ prefix marks stored-hash material, which cannot be replayed as a credential, so PASSWORD_* next to a high-entropy 53-char body must be excluded by the $2[aby]$ prefix check, not by entropy.",
    text: `// app/test/fixtures/passwords.ts
export const PASSWORD_FIXTURE_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"`,
  },
  {
    label: "certificate-body-without-pem",
    reason:
      "Base64 DER of a public X.509 certificate, 448 chars in 64-char lines. Without BEGIN/END headers no private-key rule applies, and certificate bodies are public data by design.",
    text: `The sidecar exposes the leaf certificate body as bare base64, no PEM framing:

${CERT_BODY}

Decode it to DER before inspecting the SANs.`,
  },
  {
    label: "minified-js-bundle",
    reason:
      "Minified bundle: one 2000+ char line of dense syntax and high per-character entropy, but no keyword-anchored assignment and no provider format. Size and density alone must not produce a finding.",
    text: `/*! opencode-redactor v0.2.1 | MIT | (c) 2026 OpenCode contributors */
${MINIFIED_BUNDLE}`,
  },
  {
    label: "git-diff-identifier-assignments",
    reason:
      "Diff where apiKey, secret and password are assigned from vault, keychain and env lookups. The only literals are names of other things; keyword rules must require an assigned literal and must reject short dictionary-like strings.",
    text: `diff --git a/src/config.ts b/src/config.ts
index 4d2a6c9..8ec3b1f 100644
--- a/src/config.ts
+++ b/src/config.ts
@@ -12,9 +12,11 @@ export async function loadConfig(env: Env): Promise<Config> {
-  const apiKey = env.API_KEY ?? ""
-  const secret = ""
-  const password = ""
+  const apiKey = await getFromVault("OPENAI_API_KEY")
+  const secret = await secretsManager.get("session-token")
+  const password = await keychain.lookup("payments/db")
-  return { apiKey, secret, password }
+  return { apiKey, secret, password, region: env.AWS_REGION }
 }`,
  },
  {
    label: "keyword-shaped-identifiers",
    reason:
      "Variables named apiKey, secret, token and password, each assigned a call or an env reference. Names and lookups are not values; no literal here can be fingerprinted.",
    text: `export async function loadClients(): Promise<Clients> {
  const apiKey = process.env.OPENAI_API_KEY ?? ""
  const secret = await vault.read("tenants/default")
  const token = await auth.issueServiceToken(serviceAccount)
  const password = await keychain.lookup("payments/db")
  return { apiKey, secret, token, password }
}`,
  },
  {
    label: "english-prose-paragraph",
    reason:
      "Ordinary English prose. Word boundaries and common letter frequencies hold character entropy near 4.1 bits, so natural language cannot reach a credential threshold.",
    text: "Incident response is mostly reading. The on-call engineer opens the dashboard, checks whether the alert is new or a long-running annoyance, then decides whether to page the service owner. Most alerts resolve themselves during the next deploy window; the ones that do not leave a trail of notes that the next person on shift has to reconstruct from scratch. A good runbook shortens that reconstruction by recording what was already tried and what it changed. When the alert is real, the fastest path is usually to stop the bleeding first and understand the cause second.",
  },
  {
    label: "jwt-io-sample-token",
    reason:
      "The default sample token from the jwt.io debugger, reproduced in countless tutorials. It is structurally identical to a live JWT, so it cannot be excluded by pattern; it requires an exact-value allowlist while arbitrary JWTs remain findings.",
    text: "The jwt.io debugger opens with eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c pasted into its editable pane as a demonstration.",
  },
  {
    label: "png-data-uri",
    reason:
      "Inline 1x1 PNG as a data: URI. The payload is public image bytes, so the data: scheme must be recognized and skipped instead of entropy-scanned.",
    text: `.badge {
  background-image: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==");
}`,
  },
  {
    label: "utility-class-list",
    reason:
      "Tailwind-style utility classes: hyphenated lowercase dictionary words. A long token chain is still words, so no per-token entropy gate may fire and no provider format matches.",
    text: `export function CardActions({ children }: Props) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-neutral-200 bg-white px-3 py-2 text-sm font-medium text-neutral-700 shadow-sm transition hover:bg-neutral-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 disabled:cursor-not-allowed disabled:opacity-50">
      {children}
    </div>
  )
}`,
  },
  {
    label: "long-import-list",
    reason:
      "A long import list, including module paths that mention credentials and keys. Module specifiers and imported symbol names are identifiers, not assigned values, and must stay out of the findings.",
    text: `import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http"
import { readFile, writeFile, mkdir, rm, stat, readdir } from "node:fs/promises"
import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto"
import { resolve, join, dirname, basename, extname } from "node:path"
import { parseArgs } from "node:util"
import { pipeline } from "node:stream/promises"
import { createInterface } from "node:readline/promises"
import { Buffer } from "node:buffer"
import { setTimeout as delay } from "node:timers/promises"
import { rotateSigningKey, verifyServiceToken } from "../credentials/keys"`,
  },
  {
    label: "lockfile-dependency-block",
    reason:
      "package-lock v3 block: package names, versions, registry URLs and sha512 integrity digests. Registry metadata has no secret-anchored assignment, and content hashes must not be fingerprinted as credentials.",
    text: `{
  "name": "opencode-redactor",
  "version": "0.2.1",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "node_modules/@types/node": {
      "version": "20.11.5",
      "resolved": "https://registry.npmjs.org/@types/node/-/node-20.11.5.tgz",
      "integrity": "sha512-FP0WwFU13z1js8p69G+1YolcgLPKAdzGdfCSeYPMbX6ynfTt/QEw+b9LZ4IFkaT+9pdntQSLNbj5P00kGEzc2A==",
      "dev": true
    },
    "node_modules/undici-types": {
      "version": "5.26.5",
      "resolved": "https://registry.npmjs.org/undici-types/-/undici-types-5.26.5.tgz",
      "integrity": "sha512-jEEXv2xI2XGnuzYFJ5Gqld5y0HIt96H0INp0zJfVdLTBXxQWr7e0lP+HY4Po0B5Y/CMT/i2O3zDLaCeW4bcryw=="
    },
    "node_modules/zod": {
      "version": "3.22.4",
      "resolved": "https://registry.npmjs.org/zod/-/zod-3.22.4.tgz",
      "integrity": "sha512-YZKj1fKwwvkzMFuPH2kj8HfUS20EQbDy1sdUaHHg7WwPOX+AqesoCoZ088KLFLkLpKC5ceisGyDR17UJVWnz+w=="
    }
  }
}`,
  },
  {
    label: "hex-colors-and-bit-flags",
    reason:
      "Hex colors (# plus 6 digits) and 32-bit flags (0x plus at most 8 digits). Every run is shorter than a digest or credential body, and the anchors mark display values.",
    text: `export const palette = {
  neutral900: "#111827",
  neutral700: "#374151",
  blue500: "#3B82F6",
  blue300: "#93C5FD",
  emerald400: "#34D399",
  amber300: "#FCD34D",
} as const

export const NO_FLAGS = 0x00000000
export const ALL_FLAGS = 0xffffffff
export const MAGIC = 0xdeadbeef`,
  },
  {
    label: "email-address",
    reason:
      "An email address in the reserved example.com namespace. The at-sign and dot separate local part from domain; nothing here is a value to fingerprint.",
    text: "Report suspected leaks to security@example.com and the maintainers will open a private advisory.",
  },
  {
    label: "url-with-query-string",
    reason:
      "URL with query string: path segments and plain parameters only. Query values must each be checked for credential shapes rather than the URL being flagged wholesale.",
    text: "The docs build hits https://api.example.com/v2/search?q=redaction&page=2&limit=50&sort=updated_at to refresh the search index.",
  },
  {
    label: "iso-timestamp-log-line",
    reason:
      "ISO-8601 timestamp and a duration in a log line. Digit-heavy but with fixed separators, so date and time shapes must be excluded before entropy is computed.",
    text: "2026-03-14T09:26:53.589Z ERROR [redactor] detector registry warmup took 412ms",
  },
  {
    label: "ssh-public-key",
    reason:
      "SSH public key line in authorized_keys form. Only private key material is credential-shaped; a public key is published by definition, so the ssh-rsa prefix must exempt the body from entropy scoring.",
    text: `ci-runner authorized_keys entry:

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfw8LCj3sKDoj+vWYX+gueB7Z0pEtSmlKqUZgBMWII1KBQ4j0IlmpUcE5Qrc1kOAtS7UQgHYRJChnk1L7CS5D6qovw+eQObn+eE/X2V+PGxxGFZ368SChUzV5GDRghNlY/pR3dzfBBfwnbjZ1+FTySQ068ZBBjJVaFNeqNoFvVQekddrYZxiTrBZEP6NMJzaU7RwSmMTqkCl7Ypp3AUlOfAyJcdfLX/bCwQtle30pS+7HDLGoO2NyQXwVWf/Ppw5hoPzpRXYNQGu/8yAz6CzD48Ey4YIo6QIBpDyTDiklggkR1gDx2+z+jnvBHVUT6jN2/tXP/VU180FrFB6a7 deploy@ci.example.com`,
  },
  {
    label: "oauth-endpoint-urls",
    reason:
      "OAuth endpoints in a service-account file sit under token-shaped keys, but a URL with no userinfo is an address. Credentials in a URL's userinfo are a separate Tier A rule.",
    text: `{
  "type": "service_account",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs"
}`,
  },
  {
    label: "secret-read-from-environment",
    reason:
      "A credential-named key assigned from another variable. The value is a reference to where the secret lives, not the secret, and it is what correctly written code looks like.",
    text: `const db = new Client({
  password: process.env.DATABASE_PASSWORD_PRIMARY,
  apiKey: config.services.payments.apiKey,
})`,
  },
  {
    label: "basic-auth-in-prose",
    reason:
      "The words Basic and Bearer in an explanation of HTTP auth schemes. Only an actual credential following the scheme name is a secret.",
    text: "The gateway accepts Basic authentication for legacy clients and Bearer tokens for everything else; see the auth guide for details.",
  },
  {
    label: "env-dump-paths",
    reason:
      "Shell environment output. Filesystem paths under credential-named variables point at where a secret is stored, they are not the secret.",
    text: `GOOGLE_APPLICATION_CREDENTIALS=/home/dev/.config/gcloud/application_default_credentials.json
SSL_KEY_FILE=/etc/ssl/private/server.key
PWD=/home/dev/projects/payments-service`,
  },
  {
    label: "credential-prefixes-in-prose",
    reason:
      "A sentence that names provider token prefixes without reproducing a token. hf_, gsk_, dapi, xoxb- and sk-or-v1- are only anchors; without the fixed-length body each one requires there is nothing to redact.",
    text: "Provider tokens all carry a prefix: hf_ for Hugging Face, gsk_ for Groq, dapi for Databricks, xoxb- for Slack bots and sk-or-v1- for OpenRouter. Naming the prefix in the docs is not a leak.",
  },
  {
    label: "azure-parameter-names-in-prose",
    reason:
      "Azure's AccountKey= and sig= markers named without their values. The assignment operator is not a credential on its own; the storage key and the shared-access signature are the fixed-length payloads that follow each marker.",
    text: "Azure puts the storage key after AccountKey= in the connection string and the shared-access signature after sig= in the query string. Neither marker is a credential by itself.",
  },
  {
    label: "webhook-endpoint-hosts-without-token",
    reason:
      "Slack and Discord webhook host paths quoted in documentation with no token segment. The host path is public; only the trailing secret in a complete webhook URL authenticates a post.",
    text: "The integration guide points at https://hooks.slack.com/services/ and https://discord.com/api/webhooks/ as the endpoints to configure; paste the generated URL from each service's settings page.",
  },
  {
    label: "pem-header-named-in-prose",
    reason:
      "A PEM header quoted in an explanation, with no key body after it. Only key material is a credential; the marker alone tells the reader what to look for.",
    text: `Never commit a file that starts with -----BEGIN RSA PRIVATE KEY-----
Add it to .gitignore and rotate the key if it was ever pushed.`,
  },
]

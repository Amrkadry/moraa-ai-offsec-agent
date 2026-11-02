/* moraa-ai-offsec-agent synthetic fixture bundle (tests/fixtures/js/small_bundle.js).
   Every "secret" below is an obviously-fake placeholder; the AWS key is AWS's own
   published documentation example key. No real credential appears in this file.
   Values whose provider pattern would trip a hosted secret scanner are stored as
   a bare provider prefix plus a placeholder marker, and are expanded to
   full-shape test values at load time by tests/test_js_recon.py. */
(function fixtureBundle() {
  var awsKeyId = "AKIAIOSFODNN7EXAMPLE";
  var awsTempId = "ASIA@@FIXTURE@@";
  var googleKey = "AIzaSyA-0000-EXAMPLE-FIXTURE-000000000000000";
  var googleOAuth = "ya29.@@FIXTURE@@";
  var stripeSecret = "sk_live_@@FIXTURE@@";
  var stripeRestricted = "rk_live_@@FIXTURE@@";
  var slackToken = "xoxb-@@FIXTURE@@";
  var githubToken = "ghp_@@FIXTURE@@";
  var gitlabToken = "glpat-@@FIXTURE@@";
  var sessionJwt = "eyJhbGciOiJleGFtcGxlIn0.eyJzdWIiOiJmaXh0dXJlIn0";
  var pemHeader = "-----BEGIN EXAMPLE PRIVATE KEY-----";
  var mongoUri = "mongodb+srv://fixture_user:fixture_pw@mongo.fixture.invalid/fixturedb";
  var pgUri = "postgres://fixture_user:fixture_pw@db.fixture.invalid/fixturedb";
  var myUri = "mysql://fixture_user:fixture_pw@db.fixture.invalid/fixturedb";
  var fbRef = "https://fixture-app.firebaseio.com";
  fetch("/api/v2/users");
  fetch("/internal/health");
  post("/graphql");
  post("/oauth/token");
  get("/v1/accounts/9");
  var apiBase = "https://api.fixture-example.invalid";
  var cdnBase = "https://cdn.fixture-example.invalid:8443";
  window.__CONFIG__ = { REACT_APP_GRAPHQL_URL: apiBase + "/graphql",
                        VITE_API_BASE: apiBase, NEXT_PUBLIC_CDN_HOST: cdnBase };
  __ENV__ = { NG_APP_VERSION: "9.9.9-fixture" };
  var routes = [{ path: "/dashboard" }, { route: '/admin/settings' }];
})();

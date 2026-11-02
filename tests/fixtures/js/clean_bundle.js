/* clean fixture bundle - no secrets, no endpoints, no routes, no hosts. */
function fixtureAdd(a, b) { return a + b; }
var fixtureList = [1, 2, 3].map(function (n) { return n * 2; });
module.exports = { fixtureAdd: fixtureAdd, version: "0.0.0-fixture" };

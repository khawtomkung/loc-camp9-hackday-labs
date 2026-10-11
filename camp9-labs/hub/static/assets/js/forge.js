/* Village Trading Hub — Enchanted Anvil (forge) controller
 * Served to every visitor of /forge and executed entirely in the browser.
 */

// Role of the villager currently using the forge. Normal players are "PLAYER".
var CURRENT_ROLE = "PLAYER";

// Ask the forge service to actually repair the sword. The server only hands
// back the reward when it is given the mayor's override code.
function showFlag(role) {
  fetch("/api/forge/repair", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ override: role })
  })
    .then(function (res) { return res.json(); })
    .then(function (data) {
      var box = document.getElementById("forge-result");
      box.textContent = "Diamond Sword repaired! Mayor reward: " + data.flag;
      box.style.display = "block";
    })
    .catch(function () { alert("Forge service unreachable."); });
}

// CLIENT-SIDE authorization check — this is the vulnerability being taught.
// The gate runs in the player's own browser, so the player controls the input.
function unlockMayorForge(role) {
  if (role === "MAYOR_2026") {       // mayor override from the 2026 village election
    showFlag(role);
  } else {
    alert("Access Denied");
  }
}

// Expose the gate globally so the on-page button (and the Console) can reach it.
window.unlockMayorForge = unlockMayorForge;

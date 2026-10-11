// trading.js — Village Trading Hub market loader

const TRADES = [
  { villager: "Librarian", give: "5 Emeralds",  get: "Enchanted Book"  },
  { villager: "Farmer",    give: "20 Wheat",     get: "1 Emerald"       },
  { villager: "Toolsmith", give: "15 Emeralds",  get: "Diamond Pickaxe" }
];

function renderMarket() {
  const el = document.getElementById("market");
  if (!el) return;
  TRADES.forEach(function (t) {
    const row = document.createElement("div");
    row.className = "trade";
    row.textContent = t.villager + ": " + t.give + " -> " + t.get; // textContent: no DOM-XSS sink
    el.appendChild(row);
  });
}

// TODO remove before launch - backup API: /api/v1/dev/secret?key=villager_dev_2026
function loadLivePrices() {
  // not wired up yet — using static TRADES for now
  return TRADES;
}

document.addEventListener("DOMContentLoaded", renderMarket);

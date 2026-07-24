import express from "express";
import mysql from "mysql2/promise";
import os from "node:os";
import crypto from "node:crypto";
import fs from "node:fs";
import { compactPortalKnowledge } from "./portal-knowledge.js";

const app = express();
const port = Number(process.env.PORT || 3000);
const realmName = process.env.REALM_NAME || "AzerothCore";
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || sessionSecret.length < 32) {
  throw new Error("SESSION_SECRET must be set to at least 32 characters.");
}
const registrationEnabled = String(process.env.REGISTRATION_ENABLED || "true").toLowerCase() === "true";
const registrationAnswer = String(process.env.REGISTRATION_ANSWER || "example").toLowerCase();
const registrationGateAttempts = new Map();
const launcherLoginAttempts = new Map();
const clientDownloadPath = process.env.CLIENT_DOWNLOAD_PATH || "/downloads/game-client.zip";
const clientDownloadName = process.env.CLIENT_DOWNLOAD_NAME || "game-client.zip";
const launcherDownloadPath = process.env.LAUNCHER_DOWNLOAD_PATH || "/downloads/launcher.zip";
const launcherDownloadName = process.env.LAUNCHER_DOWNLOAD_NAME || "launcher.zip";
const launcherTokenDays = Math.min(Math.max(Number(process.env.LAUNCHER_TOKEN_DAYS || 7), 1), 30);
const trackedLootQualities = new Set([3, 4, 5]);
const itemClassNames = {
  0: "Consumable",
  1: "Container",
  2: "Weapon",
  3: "Gem",
  4: "Armor",
  5: "Reagent",
  6: "Projectile",
  7: "Trade Goods",
  9: "Recipe",
  11: "Quiver",
  12: "Quest",
  13: "Key",
  15: "Miscellaneous",
  16: "Glyph"
};

const db = mysql.createPool({
  host: process.env.DB_HOST || "127.0.0.1",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "acore",
  password: process.env.DB_PASSWORD || "acore",
  waitForConnections: true,
  connectionLimit: Math.min(Math.max(Number(process.env.DB_POOL || 20), 4), 50),
  queueLimit: Math.min(Math.max(Number(process.env.DB_QUEUE_LIMIT || 100), 10), 1000),
  namedPlaceholders: true
});

app.set("trust proxy", process.env.TRUST_PROXY || "loopback, linklocal, uniquelocal");

app.use((req, res, next) => {
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet, noimageindex");
  next();
});
app.use(express.static("public", { maxAge: "5m" }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatGold(copper) {
  const value = Number(copper || 0);
  const gold = Math.floor(value / 10000);
  const silver = Math.floor((value % 10000) / 100);
  const copperPart = value % 100;
  if (gold) return `${gold}g ${silver}s`;
  if (silver) return `${silver}s ${copperPart}c`;
  return `${copperPart}c`;
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function signValue(value) {
  return crypto.createHmac("sha256", sessionSecret).update(value).digest("base64url");
}

function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || "")
    .split(";")
    .map(part => part.trim())
    .filter(Boolean)
    .map(part => {
      const index = part.indexOf("=");
      return index === -1 ? [part, ""] : [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
    }));
}

function createSessionToken(user) {
  const payload = base64url(JSON.stringify({
    id: user.id,
    username: user.username,
    isAdmin: Boolean(user.isAdmin || user.is_admin),
    exp: Date.now() + 1000 * 60 * 60 * 24 * 14
  }));
  return `${payload}.${signValue(payload)}`;
}

function currentUser(req) {
  const token = parseCookies(req).acore_portal_session;
  if (!token) return null;
  const [payload, signature] = token.split(".");
  if (!payload || !signature || signValue(payload) !== signature) return null;

  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!parsed.id || !parsed.username || Number(parsed.exp) < Date.now()) return null;
    return { id: Number(parsed.id), username: String(parsed.username), isAdmin: Boolean(parsed.isAdmin) };
  } catch {
    return null;
  }
}

function isSecureRequest(req) {
  const forwardedProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  return Boolean(req.secure || forwardedProto === "https");
}

function cookieSecurity(req) {
  return isSecureRequest(req) ? "; Secure" : "";
}

function setSession(req, res, user) {
  res.setHeader("Set-Cookie", `acore_portal_session=${encodeURIComponent(createSessionToken(user))}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 14}${cookieSecurity(req)}`);
}

function addCookie(res, cookie) {
  const existing = res.getHeader("Set-Cookie");
  if (!existing) return res.setHeader("Set-Cookie", cookie);
  return res.setHeader("Set-Cookie", Array.isArray(existing) ? [...existing, cookie] : [existing, cookie]);
}

function clearSession(req, res) {
  addCookie(res, `acore_portal_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${cookieSecurity(req)}`);
}

function requestIp(req) {
  return String(req.ip || req.socket.remoteAddress || "unknown").trim();
}

function pruneExpiringMap(map, now = Date.now(), maxEntries = 2000) {
  for (const [key, value] of map.entries()) {
    const expiresAt = Number(value?.expiresAt || value?.resetAt || 0);
    if (expiresAt && expiresAt <= now) map.delete(key);
  }
  while (map.size > maxEntries) {
    const oldestKey = map.keys().next().value;
    if (oldestKey === undefined) break;
    map.delete(oldestKey);
  }
}

function registrationGateStatus(req) {
  const cookieStatus = parseCookies(req).acore_portal_register_gate;
  pruneExpiringMap(registrationGateAttempts);
  const ipEntry = registrationGateAttempts.get(requestIp(req));
  const ipStatus = typeof ipEntry === "string" ? ipEntry : ipEntry?.status;
  if (cookieStatus === "failed" || ipStatus === "failed") return "failed";
  if (cookieStatus === "passed" || ipStatus === "passed") return "passed";
  return "new";
}

function setRegistrationGate(res, req, status) {
  pruneExpiringMap(registrationGateAttempts);
  const maxAge = status === "passed" ? 60 * 60 * 2 : 60 * 60 * 24 * 30;
  registrationGateAttempts.set(requestIp(req), { status, expiresAt: Date.now() + maxAge * 1000 });
  addCookie(res, `acore_portal_register_gate=${status}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${cookieSecurity(req)}`);
}

function passwordHash(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(password, salt, 150000, 32, "sha256").toString("hex");
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  const actual = Buffer.from(passwordHash(password, salt).hash, "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function cleanAccountName(value) {
  const username = String(value || "").trim().toUpperCase();
  if (!/^[A-Z0-9_]{3,32}$/.test(username)) throw new Error("Use 3-32 letters, numbers, or underscores for the account name.");
  return username;
}

function cleanAccountPassword(value) {
  const password = String(value || "");
  if (password.length < 6 || password.length > 32) throw new Error("Use a password between 6 and 32 characters.");
  if (!/^[A-Za-z0-9_!@#$%^*+=.?-]+$/.test(password)) throw new Error("Password contains unsupported characters.");
  return password;
}

function cleanEmail(value) {
  const email = String(value || "").trim();
  if (!email) return "";
  if (email.length > 255 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("Enter a valid email address.");
  return email;
}

function cleanDeviceName(value) {
  return String(value || "")
    .trim()
    .replace(/[^\w .()[\]-]/g, "")
    .slice(0, 80);
}

function tokenHash(token) {
  return crypto.createHash("sha256").update(String(token || "")).digest("hex");
}

function mysqlUtcDate(date) {
  return date.toISOString().slice(0, 19).replace("T", " ");
}

function parseOptionalDate(value, fallback = null) {
  if (!value) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return date;
}

function mysqlOptionalDate(value, fallback = null) {
  const date = parseOptionalDate(value, fallback);
  return date ? mysqlUtcDate(date) : null;
}

function jsonError(res, status, message) {
  return res.status(status).json({ error: message });
}

function requireLauncherHttps(req, res, next) {
  const host = String(req.headers.host || "");
  const forwardedProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  const localHost = /^(localhost|127\.0\.0\.1|192\.168\.1\.111)(?::\d+)?$/i.test(host);
  if (req.secure || forwardedProto === "https" || localHost) return next();
  return jsonError(res, 426, "Launcher authentication requires HTTPS.");
}

function launcherLoginRateLimit(req, username) {
  const key = `${requestIp(req)}:${username}`;
  const now = Date.now();
  pruneExpiringMap(launcherLoginAttempts, now);
  const windowMs = 10 * 60 * 1000;
  const limit = 8;
  const current = launcherLoginAttempts.get(key) || { count: 0, resetAt: now + windowMs };
  if (current.resetAt < now) {
    current.count = 0;
    current.resetAt = now + windowMs;
  }
  current.count += 1;
  launcherLoginAttempts.set(key, current);
  return current.count <= limit;
}

function resetLauncherLoginRateLimit(req, username) {
  launcherLoginAttempts.delete(`${requestIp(req)}:${username}`);
}

function deriveSetNameFromItems(names, setId) {
  const cleanNames = (names || []).map(name => String(name || "").trim()).filter(Boolean);
  if (!cleanNames.length) return `Item Set ${setId}`;
  const possessive = cleanNames
    .map(name => name.match(/^(.+?'s)\s+/)?.[1])
    .find(Boolean);
  if (possessive) return `${possessive} Set`;

  let prefix = cleanNames[0];
  for (const name of cleanNames.slice(1)) {
    let index = 0;
    while (index < prefix.length && index < name.length && prefix[index].toLowerCase() === name[index].toLowerCase()) index += 1;
    prefix = prefix.slice(0, index).trim();
  }
  return prefix.length >= 4 ? `${prefix} Set` : `Item Set ${setId}`;
}

function fallbackBonusesForPieceCount(pieceCount) {
  if (pieceCount >= 8) return [2, 4, 6, 8].map(threshold => ({
    threshold,
    spellId: 0,
    name: `${threshold}-Piece Set Bonus`,
    description: "Bonus details are not available in the local AzerothCore item set tables."
  }));
  if (pieceCount >= 5) return [2, 4].map(threshold => ({
    threshold,
    spellId: 0,
    name: `${threshold}-Piece Set Bonus`,
    description: "Bonus details are not available in the local AzerothCore item set tables."
  }));
  return [{
    threshold: 2,
    spellId: 0,
    name: "Set Bonus",
    description: "Bonus details are not available in the local AzerothCore item set tables."
  }];
}

const raceNames = {
  1: "Human",
  2: "Orc",
  3: "Dwarf",
  4: "Night Elf",
  5: "Undead",
  6: "Tauren",
  7: "Gnome",
  8: "Troll",
  10: "Blood Elf",
  11: "Draenei"
};

const classNames = {
  1: "Warrior",
  2: "Paladin",
  3: "Hunter",
  4: "Rogue",
  5: "Priest",
  6: "Death Knight",
  7: "Shaman",
  8: "Mage",
  9: "Warlock",
  11: "Druid"
};

const classSlugs = {
  1: "warrior",
  2: "paladin",
  3: "hunter",
  4: "rogue",
  5: "priest",
  6: "dk",
  7: "shaman",
  8: "mage",
  9: "warlock",
  11: "druid"
};

const classColors = {
  1: "#c79c6e",
  2: "#f58cba",
  3: "#abd473",
  4: "#fff569",
  5: "#f4f4f4",
  6: "#c41f3b",
  7: "#0070de",
  8: "#69ccf0",
  9: "#9482c9",
  11: "#ff7d0a"
};

const classIconNames = {
  1: "classicon_warrior",
  2: "classicon_paladin",
  3: "classicon_hunter",
  4: "classicon_rogue",
  5: "classicon_priest",
  6: "classicon_deathknight",
  7: "classicon_shaman",
  8: "classicon_mage",
  9: "classicon_warlock",
  11: "classicon_druid"
};

const itemSetFallbacks = {
  206: {
    name: "Giantstalker Armor",
    bonuses: [
      {
        threshold: 3,
        spellId: 0,
        name: "Improved Mend Pet",
        description: "Increases the range of Mend Pet by 50%, increases its effect by 10%, and reduces its cost by 30%."
      },
      {
        threshold: 5,
        spellId: 0,
        name: "Nature's Ally",
        description: "Increases your pet's stamina by 30 and all spell resistances by 40."
      },
      {
        threshold: 8,
        spellId: 0,
        name: "Giantstalker Precision",
        description: "Increases the damage of Multi-Shot and Volley by 15%."
      }
    ]
  }
};

const specSignatures = {
  1: [
    { name: "Arms", spells: [12294, 12328, 12712, 46855, 46924, 64976] },
    { name: "Fury", spells: [12292, 12974, 23881, 29801, 46917, 56927] },
    { name: "Protection", spells: [12809, 12975, 20243, 29144, 46953, 46968, 47296, 57499] }
  ],
  2: [
    { name: "Holy", spells: [20208, 20473, 31821, 31836, 31841, 31842, 53557, 53563, 53576, 54155] },
    { name: "Protection", spells: [20925, 31850, 31860, 31935, 53592, 53595] },
    { name: "Retribution", spells: [20066, 31869, 31879, 35395, 53385] }
  ],
  3: [
    { name: "Beast Mastery", spells: [19574, 19577, 34460, 34692, 53270] },
    { name: "Marksmanship", spells: [19434, 19506, 23989, 34490, 53209, 53217] },
    { name: "Survival", spells: [3674, 19386, 19503, 53301, 53292] }
  ],
  4: [
    { name: "Assassination", spells: [1329, 14177, 51662, 51667, 58426] },
    { name: "Combat", spells: [13750, 13877, 32601, 35553, 51682, 51690] },
    { name: "Subtlety", spells: [14183, 14185, 16511, 36554, 51713] }
  ],
  5: [
    { name: "Discipline", spells: [10060, 33206, 47540, 52798] },
    { name: "Holy", spells: [724, 20711, 34861, 47788] },
    { name: "Shadow", spells: [15286, 15473, 15487, 34914, 47585] }
  ],
  6: [
    { name: "Blood", spells: [49016, 49028, 55050, 55233] },
    { name: "Frost", spells: [49143, 49184, 49203, 51271] },
    { name: "Unholy", spells: [49194, 49206, 49222, 55090] }
  ],
  7: [
    { name: "Elemental", spells: [16166, 30706, 51482, 51490] },
    { name: "Enhancement", spells: [17364, 30798, 30823, 51533, 60103] },
    { name: "Restoration", spells: [974, 16188, 16190, 61295] }
  ],
  8: [
    { name: "Arcane", spells: [12042, 12043, 31589, 44425] },
    { name: "Fire", spells: [11113, 11129, 11366, 31661, 44457] },
    { name: "Frost", spells: [11426, 11958, 12472, 31687, 44572] }
  ],
  9: [
    { name: "Affliction", spells: [17805, 30108, 32383, 48181, 58435, 63108] },
    { name: "Demonology", spells: [19028, 30146, 47193, 47241] },
    { name: "Destruction", spells: [17962, 30283, 47258, 50796] }
  ],
  11: [
    { name: "Balance", spells: [24858, 33831, 48505, 50516] },
    { name: "Feral", spells: [17007, 33876, 33878, 50334, 61336] },
    { name: "Restoration", spells: [17116, 18562, 33891, 48438] }
  ]
};

const genderNames = {
  0: "Male",
  1: "Female"
};

const titleNames = {
  78: "the Explorer",
  124: "the Hallowed",
  127: "of the Horde",
  142: "the Immortal",
  155: "the Noble"
};

const qualityNames = {
  0: "Poor",
  1: "Common",
  2: "Uncommon",
  3: "Rare",
  4: "Epic",
  5: "Legendary",
  6: "Artifact",
  7: "Heirloom"
};

const equipmentGroups = [
  {
    title: "Armor",
    slots: [
      { slot: 0, label: "Head" },
      { slot: 2, label: "Shoulders" },
      { slot: 14, label: "Back" },
      { slot: 4, label: "Chest" },
      { slot: 8, label: "Wrists" },
      { slot: 9, label: "Hands" },
      { slot: 5, label: "Waist" },
      { slot: 6, label: "Legs" },
      { slot: 7, label: "Feet" }
    ]
  },
  {
    title: "Accessories",
    slots: [
      { slot: 1, label: "Neck" },
      { slot: 10, label: "Ring" },
      { slot: 11, label: "Ring" },
      { slot: 12, label: "Trinket" },
      { slot: 13, label: "Trinket" },
      { slot: 3, label: "Shirt" },
      { slot: 18, label: "Tabard" }
    ]
  },
  {
    title: "Weapons",
    slots: [
      { slot: 15, label: "Main Hand" },
      { slot: 16, label: "Off Hand" },
      { slot: 17, label: "Ranged" }
    ]
  }
];

const combatGearSlots = new Set([0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]);
const mapNames = {
  0: "Eastern Kingdoms",
  1: "Kalimdor",
  30: "Alterac Valley",
  33: "Shadowfang Keep",
  34: "Stormwind Stockade",
  36: "Deadmines",
  43: "Wailing Caverns",
  47: "Razorfen Kraul",
  48: "Blackfathom Deeps",
  70: "Uldaman",
  90: "Gnomeregan",
  109: "Sunken Temple",
  129: "Razorfen Downs",
  189: "Scarlet Monastery",
  209: "Zul'Farrak",
  229: "Blackrock Spire",
  230: "Blackrock Depths",
  249: "Onyxia's Lair",
  269: "Opening of the Dark Portal",
  289: "Scholomance",
  309: "Zul'Gurub",
  329: "Stratholme",
  349: "Maraudon",
  369: "Deeprun Tram",
  389: "Ragefire Chasm",
  409: "Molten Core",
  429: "Dire Maul",
  469: "Blackwing Lair",
  489: "Warsong Gulch",
  509: "AQ20 - Ruins of Ahn'Qiraj",
  529: "Arathi Basin",
  530: "Outland",
  531: "Ahn'Qiraj Temple",
  532: "Karazhan",
  533: "Naxxramas",
  534: "Hyjal Summit",
  540: "Shattered Halls",
  542: "Blood Furnace",
  543: "Hellfire Ramparts",
  544: "Magtheridon's Lair",
  545: "Steamvault",
  546: "Underbog",
  547: "Slave Pens",
  548: "Serpentshrine Cavern",
  550: "Tempest Keep",
  552: "Arcatraz",
  553: "Botanica",
  554: "Mechanar",
  555: "Shadow Labyrinth",
  556: "Sethekk Halls",
  557: "Mana-Tombs",
  558: "Auchenai Crypts",
  559: "Nagrand Arena",
  560: "Old Hillsbrad",
  562: "Blade's Edge Arena",
  564: "Black Temple",
  565: "Gruul's Lair",
  566: "Eye of the Storm",
  568: "Zul'Aman",
  571: "AzerothCore",
  572: "Ruins of Lordaeron",
  574: "Utgarde Keep",
  575: "Utgarde Pinnacle",
  576: "The Nexus",
  578: "The Oculus",
  580: "Sunwell Plateau",
  585: "Magisters' Terrace",
  595: "Culling of Stratholme",
  599: "Halls of Stone",
  600: "Drak'Tharon Keep",
  601: "Azjol-Nerub",
  602: "Halls of Lightning",
  603: "Ulduar",
  604: "Gundrak",
  608: "Violet Hold",
  615: "Obsidian Sanctum",
  616: "Eye of Eternity",
  617: "Dalaran Sewers",
  618: "Ring of Valor",
  619: "Ahn'kahet",
  624: "Vault of Archavon",
  631: "Icecrown Citadel",
  632: "Forge of Souls",
  649: "Trial of the Crusader",
  650: "Trial of the Champion",
  658: "Pit of Saron",
  668: "Halls of Reflection"
};

const zoneNames = {
  1: "Dun Morogh",
  12: "Elwynn Forest",
  15: "Dustwallow Marsh",
  16: "Alexston Farmstead",
  14: "Durotar",
  17: "The Barrens",
  33: "Stranglethorn Vale",
  38: "Loch Modan",
  40: "Westfall",
  85: "Tirisfal Glades",
  130: "Silverpine Forest",
  139: "Bloodvenom Post",
  141: "Teldrassil",
  148: "Darkshore",
  215: "Mulgore",
  267: "Hillsbrad Foothills",
  331: "Ashenvale",
  357: "Feralas",
  361: "Felwood",
  400: "Thousand Needles",
  405: "Desolace",
  406: "Stonetalon Mountains",
  440: "Tanaris",
  490: "Un'Goro Crater",
  493: "Moonglade",
  618: "Winterspring",
  1377: "Silithus",
  1497: "Undercity",
  1519: "Stormwind City",
  1537: "Ironforge",
  1637: "Orgrimmar",
  1638: "Thunder Bluff",
  1657: "Darnassus",
  2597: "Alterac Valley",
  3487: "Silvermoon City",
  3524: "Azuremyst Isle",
  3525: "Bloodmyst Isle",
  3557: "The Exodar",
  3703: "Shattrath City",
  4080: "Isle of Quel'Danas",
  4197: "Wintergrasp",
  4273: "Ulduar",
  4395: "Dalaran",
  4710: "Isle of Conquest"
};

const trackedWorldBosses = [
  { entry: 6109, name: "Azuregos", location: "Azshara", icon: "/portal-art/boss-dragon-blue.png" },
  { entry: 12397, name: "Lord Kazzak", location: "Blasted Lands", icon: "/portal-art/boss-demon.png" },
  { entry: 14887, name: "Ysondre", location: "Feralas", icon: "/portal-art/boss-green-dragon.png" },
  { entry: 14888, name: "Lethon", location: "The Hinterlands", icon: "/portal-art/boss-shadow-dragon.png" },
  { entry: 14889, name: "Emeriss", location: "Ashenvale", icon: "/portal-art/boss-green-dragon.png" },
  { entry: 14890, name: "Taerar", location: "Duskwood", icon: "/portal-art/boss-shadow-dragon.png" }
];

const worldBossesByEntry = new Map(trackedWorldBosses.map(boss => [Number(boss.entry), boss]));

function worldBossEntryFromRunKey(runKey = "") {
  const match = String(runKey || "").match(/^worldboss-(\d+)$/i);
  return match ? Number(match[1]) : 0;
}

function worldBossForRun(run = {}) {
  const runKey = run.sourceRunKey || run.runKey || "";
  const entry = worldBossEntryFromRunKey(runKey);
  return entry ? worldBossesByEntry.get(entry) : null;
}

function factionForRace(race) {
  return [2, 5, 6, 8, 10].includes(Number(race)) ? "Horde" : "Alliance";
}

function classBadge(classId) {
  const name = classNames[classId] || "Class";
  const slug = classSlugs[classId] || "class";
  const label = classId === 6 ? "DK" : name.slice(0, 1);
  const icon = classIconNames[classId];
  const image = icon ? `<img src="https://wow.zamimg.com/images/wow/icons/large/${icon}.jpg" alt="" loading="lazy" onerror="this.remove()">` : "";
  return `<span class="class-icon ${slug}" title="${escapeHtml(name)}">${image}<b>${escapeHtml(label)}</b></span>`;
}

function mapLabel(mapId) {
  return mapNames[Number(mapId)] || `Map ${mapId}`;
}

function zoneLabel(zoneId, dbZoneName = "") {
  return dbZoneName || zoneNames[Number(zoneId)] || `Zone ${zoneId}`;
}

function cleanSoapText(raw) {
  return raw
    .replace(/<[^>]+>/g, " ")
    .replace(/&(?:amp;)?#xD;|&(?:amp;)?#13;/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function sqlString(value) {
  return `'${String(value ?? "").replace(/\\/g, "\\\\").replace(/'/g, "''")}'`;
}

function styleOutputText(value) {
  const parts = String(value || "").split(/(\b\d+(?:\.\d+)?%?\b|\b(?:complete|completed|success|saved|online|uptime|failed|error|warning|offline)\b)/gi);
  return parts.map(part => {
    if (/^\d+(?:\.\d+)?%?$/.test(part)) return `<span class="output-number">${escapeHtml(part)}</span>`;
    if (/^(?:complete|completed|success|saved|online|uptime)$/i.test(part)) return `<span class="output-good">${escapeHtml(part)}</span>`;
    if (/^(?:failed|error|warning|offline)$/i.test(part)) return `<span class="output-bad">${escapeHtml(part)}</span>`;
    return escapeHtml(part);
  }).join("");
}

function fieldFromPinfoSegment(segment) {
  const normalized = segment.replace(/^[-\s]+/, "").trim();
  const player = normalized.match(/^Player\s+([^\s(]+)\s+\(guid:\s*(.*)\)$/i);
  if (player) return { label: "GUID", value: player[2] };

  const alive = normalized.match(/^Alive \?:\s*(.*)$/i);
  if (alive) return { label: "Alive", value: alive[1] };

  const match = normalized.match(/^([^:]{2,34}):\s*(.*)$/);
  if (!match) return null;
  return { label: match[1].trim(), value: match[2].trim() };
}

function pinfoCharacterName(raw) {
  return String(raw || "").match(/Player\s+([^\s(]+)/i)?.[1] || "";
}

async function getCharacterSpecByName(name) {
  const characterName = String(name || "").trim();
  if (!characterName) return "";

  const [rows] = await db.query(`SELECT guid, class, activeTalentGroup
    FROM acore_characters.characters
    WHERE LOWER(name) = LOWER(?)
    LIMIT 1`, [characterName]);
  if (!rows.length) return "";

  const character = rows[0];
  const guid = Number(character.guid);
  const classId = Number(character.class);
  const activeMask = 1 << Number(character.activeTalentGroup || 0);
  const [talentRows] = await db.query(`SELECT spell, specMask
    FROM acore_characters.character_talent
    WHERE guid = ?`, [guid]);

  const activeSpells = new Set(talentRows
    .filter(row => (Number(row.specMask || 0) & activeMask) !== 0)
    .map(row => Number(row.spell)));

  let best = null;
  for (const signature of specSignatures[classId] || []) {
    const score = signature.spells.filter(spell => activeSpells.has(spell)).length;
    if (!best || score > best.score) best = { name: signature.name, score };
  }

  return best && best.score > 0 ? best.name : "";
}

function renderPinfoOutput(raw, specName = "") {
  const text = String(raw || "").trim();
  const segments = text
    .split(/[¦]+|├─/g)
    .map(segment => segment.trim())
    .filter(Boolean);

  const header = segments.find(segment => /^Player\s+/i.test(segment)) || "";
  const name = header.match(/^Player\s+([^\s(]+)/i)?.[1] || "Character";
  const fields = segments.map(fieldFromPinfoSegment).filter(Boolean);
  const fieldMap = new Map(fields.map(field => [field.label.toLowerCase(), field]));
  const getField = label => fieldMap.get(label.toLowerCase())?.value || "";

  const level = getField("Level").match(/^\d+/)?.[0] || "";
  const race = getField("Race");
  const map = getField("Map");
  const guild = getField("Guild");
  const online = getField("Online for");
  const money = getField("Money");
  const account = getField("Account");

  const chips = [
    level ? { label: "Level", value: level } : null,
    specName ? { label: "Spec", value: specName } : null,
    race ? { label: "Race/Class", value: race } : null,
    online ? { label: "Online", value: online } : null,
    money ? { label: "Money", value: money } : null
  ].filter(Boolean);

  const preferred = ["Account", "Last Login", "OS", "Last IP", "Level", "Race", "Alive", "Phase", "Money", "Map", "Guild", "Rank", "Played time", "Online for", "Mails", "GUID", "Registration Email"];
  const ordered = [
    ...preferred.map(label => fields.find(field => field.label.toLowerCase() === label.toLowerCase())).filter(Boolean),
    ...fields.filter(field => !preferred.some(label => label.toLowerCase() === field.label.toLowerCase()))
  ];

  return `<div class="pinfo-card">
    <div class="pinfo-hero">
      <div>
        <span class="result-kicker">Character Profile</span>
        <h3>${escapeHtml(name)}</h3>
        <p>${map ? styleOutputText(map) : "Location unavailable"}${guild ? ` - ${styleOutputText(guild)}` : ""}</p>
      </div>
      ${account ? `<span class="pinfo-account">${styleOutputText(account)}</span>` : ""}
    </div>
    ${chips.length ? `<div class="pinfo-chips">${chips.map(chip => `<div class="pinfo-chip"><b>${escapeHtml(chip.label)}</b><strong>${styleOutputText(chip.value)}</strong></div>`).join("")}</div>` : ""}
    <div class="pinfo-grid">
      ${ordered.map(field => `<div class="pinfo-field"><span class="pinfo-label">${escapeHtml(field.label)}</span><strong>${styleOutputText(field.value || "None")}</strong></div>`).join("")}
    </div>
  </div>`;
}

function houseName(houseId) {
  return ({ 2: "Alliance", 6: "Horde", 7: "Neutral" })[Number(houseId)] || `House ${houseId}`;
}

async function getAhStatusData() {
  const [summaryRows, byHouse, byQuality, byLevel, byClass] = await Promise.all([
    query(`SELECT COUNT(*) total,
        COALESCE(SUM(buyoutprice), 0) buyoutTotal,
        COALESCE(AVG(NULLIF(buyoutprice, 0)), 0) avgBuyout,
        COALESCE(MIN(time), 0) oldest,
        COALESCE(MAX(time), 0) newest
      FROM acore_characters.auctionhouse`),
    query(`SELECT houseid, COUNT(*) count
      FROM acore_characters.auctionhouse
      GROUP BY houseid
      ORDER BY count DESC`),
    query(`SELECT it.Quality quality, COUNT(*) count
      FROM acore_characters.auctionhouse ah
      JOIN acore_characters.item_instance ii ON ii.guid = ah.itemguid
      JOIN acore_world.item_template it ON it.entry = ii.itemEntry
      GROUP BY it.Quality
      ORDER BY it.Quality`),
    query(`SELECT
        CASE
          WHEN it.RequiredLevel BETWEEN 1 AND 19 THEN '1-19'
          WHEN it.RequiredLevel BETWEEN 20 AND 39 THEN '20-39'
          WHEN it.RequiredLevel BETWEEN 40 AND 49 THEN '40-49'
          WHEN it.RequiredLevel BETWEEN 50 AND 59 THEN '50-59'
          WHEN it.RequiredLevel BETWEEN 60 AND 65 THEN '60-65'
          ELSE '66+'
        END bracket,
        COUNT(*) count
      FROM acore_characters.auctionhouse ah
      JOIN acore_characters.item_instance ii ON ii.guid = ah.itemguid
      JOIN acore_world.item_template it ON it.entry = ii.itemEntry
      GROUP BY bracket
      ORDER BY MIN(it.RequiredLevel)`),
    query(`SELECT it.class itemClass, COUNT(*) count
      FROM acore_characters.auctionhouse ah
      JOIN acore_characters.item_instance ii ON ii.guid = ah.itemguid
      JOIN acore_world.item_template it ON it.entry = ii.itemEntry
      GROUP BY it.class
      ORDER BY count DESC
      LIMIT 8`)
  ]);

  return {
    summary: summaryRows[0] || { total: 0, buyoutTotal: 0, avgBuyout: 0, oldest: 0, newest: 0 },
    byHouse,
    byQuality,
    byLevel,
    byClass
  };
}

async function getAhRangeData(minLevel, maxLevel) {
  const params = { minLevel, maxLevel };
  const [summaryRows, byHouse, byQuality, byClass, samples] = await Promise.all([
    query(`SELECT COUNT(*) total,
        COALESCE(AVG(NULLIF(ah.buyoutprice, 0)), 0) avgBuyout,
        COALESCE(SUM(CASE WHEN it.Quality >= 2 THEN 1 ELSE 0 END), 0) greenPlus,
        COALESCE(SUM(CASE WHEN it.class = 4 THEN 1 ELSE 0 END), 0) armor,
        COALESCE(SUM(CASE WHEN it.class = 2 THEN 1 ELSE 0 END), 0) weapons,
        COALESCE(SUM(CASE WHEN it.class = 7 THEN 1 ELSE 0 END), 0) tradeGoods
      FROM acore_characters.auctionhouse ah
      JOIN acore_characters.item_instance ii ON ii.guid = ah.itemguid
      JOIN acore_world.item_template it ON it.entry = ii.itemEntry
      WHERE it.RequiredLevel BETWEEN :minLevel AND :maxLevel`, params),
    query(`SELECT ah.houseid, COUNT(*) count
      FROM acore_characters.auctionhouse ah
      JOIN acore_characters.item_instance ii ON ii.guid = ah.itemguid
      JOIN acore_world.item_template it ON it.entry = ii.itemEntry
      WHERE it.RequiredLevel BETWEEN :minLevel AND :maxLevel
      GROUP BY ah.houseid
      ORDER BY count DESC`, params),
    query(`SELECT it.Quality quality, COUNT(*) count
      FROM acore_characters.auctionhouse ah
      JOIN acore_characters.item_instance ii ON ii.guid = ah.itemguid
      JOIN acore_world.item_template it ON it.entry = ii.itemEntry
      WHERE it.RequiredLevel BETWEEN :minLevel AND :maxLevel
      GROUP BY it.Quality
      ORDER BY it.Quality`, params),
    query(`SELECT it.class itemClass, COUNT(*) count
      FROM acore_characters.auctionhouse ah
      JOIN acore_characters.item_instance ii ON ii.guid = ah.itemguid
      JOIN acore_world.item_template it ON it.entry = ii.itemEntry
      WHERE it.RequiredLevel BETWEEN :minLevel AND :maxLevel
      GROUP BY it.class
      ORDER BY count DESC
      LIMIT 8`, params),
    query(`SELECT it.entry, it.name, it.Quality quality, it.RequiredLevel requiredLevel, ah.houseid, ah.buyoutprice
      FROM acore_characters.auctionhouse ah
      JOIN acore_characters.item_instance ii ON ii.guid = ah.itemguid
      JOIN acore_world.item_template it ON it.entry = ii.itemEntry
      WHERE it.RequiredLevel BETWEEN :minLevel AND :maxLevel
        AND it.Quality >= 2
      ORDER BY it.Quality DESC, it.RequiredLevel, it.name
      LIMIT 12`, params)
  ]);

  return {
    minLevel,
    maxLevel,
    summary: summaryRows[0] || { total: 0, avgBuyout: 0, greenPlus: 0, armor: 0, weapons: 0, tradeGoods: 0 },
    byHouse,
    byQuality,
    byClass,
    samples
  };
}

function renderAhStatusOutput(data) {
  const summary = data.summary;
  const total = Number(summary.total || 0);
  const classNames = {
    0: "Consumable",
    1: "Container",
    2: "Weapon",
    3: "Gem",
    4: "Armor",
    5: "Reagent",
    6: "Projectile",
    7: "Trade Goods",
    9: "Recipe",
    12: "Quest",
    15: "Misc",
    16: "Glyph"
  };
  const qualityNames = ["Poor", "Common", "Uncommon", "Rare", "Epic", "Legendary", "Artifact", "Heirloom"];
  const maxBucket = Math.max(1, ...data.byLevel.map(row => Number(row.count || 0)), ...data.byHouse.map(row => Number(row.count || 0)));
  const bars = rows => rows.map(row => {
    const label = row.bracket || houseName(row.houseid);
    const count = Number(row.count || 0);
    const pct = Math.max(2, Math.round((count / maxBucket) * 100));
    return `<div class="ah-bar"><span>${escapeHtml(label)}</span><i><b style="width:${pct}%"></b></i><strong>${count.toLocaleString()}</strong></div>`;
  }).join("");

  return `<div class="ah-status-card">
    <div class="ah-status-hero">
      <div>
        <span class="result-kicker">Auction House</span>
        <h3>${total.toLocaleString()} Auctions</h3>
        <p>Current listings across Horde, Alliance, and Neutral houses.</p>
      </div>
      <span class="ah-status-money">${escapeHtml(formatGold(Number(summary.avgBuyout || 0)))} avg buyout</span>
    </div>
    <div class="pinfo-chips">
      <div class="pinfo-chip"><b>Total Buyout</b><strong>${escapeHtml(formatGold(Number(summary.buyoutTotal || 0)))}</strong></div>
      <div class="pinfo-chip"><b>Houses</b><strong>${data.byHouse.length}</strong></div>
      <div class="pinfo-chip"><b>Quality Bands</b><strong>${data.byQuality.length}</strong></div>
      <div class="pinfo-chip"><b>Level Bands</b><strong>${data.byLevel.length}</strong></div>
    </div>
    <div class="ah-status-grid">
      <section>
        <h4>By House</h4>
        ${bars(data.byHouse)}
      </section>
      <section>
        <h4>By Level</h4>
        ${bars(data.byLevel)}
      </section>
      <section>
        <h4>By Quality</h4>
        <div class="ah-tags">${data.byQuality.map(row => `<span class="q${Number(row.quality)}">${escapeHtml(qualityNames[Number(row.quality)] || `Q${row.quality}`)} <b>${Number(row.count || 0).toLocaleString()}</b></span>`).join("")}</div>
      </section>
      <section>
        <h4>Top Item Types</h4>
        <div class="ah-tags">${data.byClass.map(row => `<span>${escapeHtml(classNames[Number(row.itemClass)] || `Class ${row.itemClass}`)} <b>${Number(row.count || 0).toLocaleString()}</b></span>`).join("")}</div>
      </section>
    </div>
  </div>`;
}

function renderAhRangeOutput(data) {
  const summary = data.summary;
  const total = Number(summary.total || 0);
  const classNames = {
    0: "Consumable",
    2: "Weapon",
    4: "Armor",
    7: "Trade Goods",
    9: "Recipe",
    15: "Misc",
    16: "Glyph"
  };
  const qualityNames = ["Poor", "Common", "Uncommon", "Rare", "Epic", "Legendary", "Artifact", "Heirloom"];
  const maxBucket = Math.max(1, ...data.byHouse.map(row => Number(row.count || 0)));
  const houseBars = data.byHouse.map(row => {
    const count = Number(row.count || 0);
    const pct = Math.max(2, Math.round((count / maxBucket) * 100));
    return `<div class="ah-bar"><span>${escapeHtml(houseName(row.houseid))}</span><i><b style="width:${pct}%"></b></i><strong>${count.toLocaleString()}</strong></div>`;
  }).join("");
  const recommendation = total < 500
    ? "This range looks thin. Raise the AHBot max stock or broaden eligible items if you want more here."
    : total < 1000
      ? "This range is usable but could be deeper."
      : "This range looks healthy.";

  return `<div class="ah-status-card">
    <div class="ah-status-hero">
      <div>
        <span class="result-kicker">Auction Range</span>
        <h3>Level ${Number(data.minLevel)}-${Number(data.maxLevel)}</h3>
        <p>${escapeHtml(recommendation)}</p>
      </div>
      <span class="ah-status-money">${total.toLocaleString()} listings</span>
    </div>
    <div class="pinfo-chips">
      <div class="pinfo-chip"><b>Avg Buyout</b><strong>${escapeHtml(formatGold(Number(summary.avgBuyout || 0)))}</strong></div>
      <div class="pinfo-chip"><b>Green+</b><strong>${Number(summary.greenPlus || 0).toLocaleString()}</strong></div>
      <div class="pinfo-chip"><b>Armor</b><strong>${Number(summary.armor || 0).toLocaleString()}</strong></div>
      <div class="pinfo-chip"><b>Weapons</b><strong>${Number(summary.weapons || 0).toLocaleString()}</strong></div>
    </div>
    <div class="ah-status-grid">
      <section>
        <h4>By House</h4>
        ${houseBars || `<p class="muted">No listings in this level range.</p>`}
      </section>
      <section>
        <h4>By Quality</h4>
        <div class="ah-tags">${data.byQuality.map(row => `<span class="q${Number(row.quality)}">${escapeHtml(qualityNames[Number(row.quality)] || `Q${row.quality}`)} <b>${Number(row.count || 0).toLocaleString()}</b></span>`).join("") || `<span>None <b>0</b></span>`}</div>
      </section>
      <section>
        <h4>Top Item Types</h4>
        <div class="ah-tags">${data.byClass.map(row => `<span>${escapeHtml(classNames[Number(row.itemClass)] || `Class ${row.itemClass}`)} <b>${Number(row.count || 0).toLocaleString()}</b></span>`).join("") || `<span>None <b>0</b></span>`}</div>
      </section>
      <section>
        <h4>Sample Green+ Items</h4>
        <div class="ah-samples">${data.samples.map(item => renderWowheadItemLink({
          entry: item.entry,
          name: item.name,
          quality: item.quality,
          content: `<strong>${escapeHtml(item.name)}</strong><span>Lvl ${Number(item.requiredLevel)} - ${escapeHtml(houseName(item.houseid))} - ${escapeHtml(formatGold(Number(item.buyoutprice || 0)))}</span>`
        })).join("") || `<p class="muted">No uncommon or better items in this level range.</p>`}</div>
      </section>
    </div>
  </div>`;
}

function renderCommandOutput(raw, actionKey = "") {
  if (actionKey === "pinfo" && /Player\s+\S+/i.test(String(raw || ""))) {
    return renderPinfoOutput(raw);
  }

  const text = String(raw || "No output returned.").trim();
  const formatted = text
    .replace(/\s+(AzerothCore rev\.?)/gi, "\n$1")
    .replace(/\s+(Server uptime|Update time diff|Players online|Active connections|Queued players|Map update time|Worldserver|Database|Characters|Accounts|Result|Message|Error|Warning)(\s*:)/gi, "\n$1$2")
    .trim();

  const rows = formatted.split(/\n+/).filter(Boolean);
  return `<div class="command-output" role="log">${rows.map(line => {
    const match = line.match(/^([^:]{2,42}):\s*(.*)$/);
    if (match) {
      return `<div class="command-output-row"><span class="output-label">${escapeHtml(match[1])}</span><span class="output-value">${styleOutputText(match[2])}</span></div>`;
    }
    return `<div class="command-output-line">${styleOutputText(line)}</div>`;
  }).join("")}</div>`;
}

function adminResultHead(actionKey) {
  if (actionKey === "ahStatus" || actionKey === "ahRestockRange") {
    return { title: "Auction house response", subtitle: "Database status" };
  }
  if (actionKey === "raidLockoutReset") {
    return { title: "Raid lockout response", subtitle: "Character database" };
  }
  if (actionKey === "raidBagCleanup") {
    return { title: "Bag cleanup response", subtitle: "Character database" };
  }
  return { title: "Worldserver response", subtitle: "SOAP output" };
}

const soapActions = {
  serverInfo: { label: "Server Info", command: () => "server info", description: "Show realm uptime and active player counts." },
  saveAll: { label: "Save All Characters", command: () => "saveall", description: "Force-save every online character." },
};

const raidLockoutTargets = {
  allClassic: { label: "All Active Level-60 Raids", maps: [309, 409, 469, 509, 531] },
  moltenCore: { label: "Molten Core", maps: [409] },
  zulGurub: { label: "Zul'Gurub", maps: [309] },
  aq20: { label: "AQ20 - Ruins of Ahn'Qiraj", maps: [509] },
  blackwingLair: { label: "Blackwing Lair", maps: [469] },
  aq40: { label: "AQ40 - Temple of Ahn'Qiraj", maps: [531] }
};

const raidMapNames = {
  249: "Onyxia's Lair",
  309: "Zul'Gurub",
  409: "Molten Core",
  469: "Blackwing Lair",
  509: "AQ20 - Ruins of Ahn'Qiraj",
  531: "AQ40 - Temple of Ahn'Qiraj",
  533: "Naxxramas"
};

const adminToolGroups = [
  {
    id: "server",
    title: "Server",
    subtitle: "Realm-wide checks and notices",
    tools: [
      { action: "serverInfo", label: "Server Info", description: "Show uptime and active players.", fields: [] },
      { action: "saveAll", label: "Save All", description: "Force-save online characters.", fields: [] },
      { action: "announce", label: "Announce", description: "Send a server-wide message.", fields: [{ name: "message", label: "Message", placeholder: "Server restart in 15 minutes", required: true }] },
      { action: "restartWarning", label: "Restart Warning", description: "Broadcast a preset restart warning.", fields: [{ name: "minutes", label: "Minutes", type: "select", options: ["15", "10", "5", "1"], required: true }] }
    ]
  },
  {
    id: "character-care",
    title: "Character Care",
    subtitle: "Look up, move, and recover characters",
    tools: [
      { action: "pinfo", label: "Character Info", description: "Detailed GM info for a character.", fields: [{ name: "character", label: "Character", placeholder: "Charactername", required: true }] },
      { action: "revive", label: "Revive", description: "Revive a dead character.", fields: [{ name: "character", label: "Character", placeholder: "Charactername", required: true }] },
      { action: "unstuck", label: "Unstuck to Inn", description: "Send a character to their hearth/inn location.", fields: [{ name: "character", label: "Character", placeholder: "Charactername", required: true }] },
      { action: "summon", label: "Summon to GM", description: "Move a character to the GM.", fields: [{ name: "character", label: "Character", placeholder: "Healername", required: true }] },
      { action: "summonToCharacter", label: "Summon to Raid Member", description: "Move one online character beside another online group or raid member, preserving live instance context.", fields: [
        { name: "character", label: "Character to Move", placeholder: "Charactername", required: true },
        { name: "destination", label: "Destination Character", placeholder: "Healername", required: true }
      ] },
      { action: "appear", label: "Go to Character", description: "Move the GM to a character.", fields: [{ name: "character", label: "Character", placeholder: "Healername", required: true }] },
      { action: "repair", label: "Repair Gear", description: "Repair a character's gear.", fields: [{ name: "character", label: "Character", placeholder: "Warlockname", required: true }] },
      { action: "summonRepairBot", label: "Summon Repair Bot", description: "Place a temporary repair bot beside an online character, including inside dungeons and battlegrounds.", fields: [
        { name: "character", label: "Character", placeholder: "Charactername", required: true },
        { name: "duration", label: "Minutes", type: "number", placeholder: "10", min: "1", max: "30" },
        { name: "entry", label: "Bot", type: "select", options: [{ value: "24780", label: "Field Repair Bot 110G" }, { value: "14337", label: "Field Repair Bot 74A" }] }
      ] }
    ]
  },
  {
    id: "character-build",
    title: "Character Build",
    subtitle: "Levels, titles, spells, and item grants",
    tools: [
      { action: "rename", label: "Flag Rename", description: "Make a character rename on next login.", fields: [{ name: "character", label: "Character", placeholder: "Oldname", required: true }] },
      { action: "level", label: "Set Level", description: "Set a character level.", fields: [{ name: "character", label: "Character", placeholder: "Shamanname", required: true }, { name: "level", label: "Level", type: "number", placeholder: "58", min: "1", max: "80", required: true }] },
      { action: "addItem", label: "Grant Item", description: "Add an item by entry ID. Mail works offline; direct bag is for online characters.", fields: [
        { name: "character", label: "Character", placeholder: "Charactername", required: true },
        { name: "entry", label: "Item ID", type: "number", placeholder: "18832", required: true },
        { name: "count", label: "Count", type: "number", placeholder: "1", min: "1" },
        { name: "delivery", label: "Delivery", type: "select", options: [{ value: "mail", label: "Mail - offline safe" }, { value: "direct", label: "Direct Bag - online only" }] }
      ] },
      { action: "learnSpell", label: "Learn Spell", description: "Teach a spell by ID.", fields: [{ name: "character", label: "Character", placeholder: "Healername", required: true }, { name: "spell", label: "Spell ID", type: "number", placeholder: "20217", required: true }] },
      { action: "resetTalents", label: "Reset Talents", description: "Reset a character's talents.", fields: [{ name: "character", label: "Character", placeholder: "Tankname", required: true }] },
      { action: "setTitle", label: "Set Title", description: "Set one of your favorite titles.", fields: [{ name: "character", label: "Character", placeholder: "Magename", required: true }, { name: "title", label: "Title", type: "select", options: Object.entries(titleNames).map(([value, label]) => ({ value, label })), required: true }] }
    ]
  },
  {
    id: "playerbots",
    title: "Playerbots",
    subtitle: "Party helpers and maintenance",
    tools: [
      { action: "botMaintenance", label: "Maintenance", description: "Run playerbot maintenance.", fields: [{ name: "character", label: "Bot", placeholder: "Healername", required: true }] },
      { action: "botReset", label: "Reset AI", description: "Reset one bot's AI state.", fields: [{ name: "character", label: "Bot", placeholder: "Shamanname", required: true }] },
      { action: "botSummon", label: "Summon Bot", description: "Summon one bot to your party.", fields: [{ name: "character", label: "Bot", placeholder: "Magename", required: true }] },
      { action: "botDismiss", label: "Dismiss Bot", description: "Dismiss one bot from party play.", fields: [{ name: "character", label: "Bot", placeholder: "Magename", required: true }] },
      { action: "raidBagCleanup", label: "Raid Bag Cleanup", description: "Dry-run or vendor unequipped soulbound green/blue gear from offline characters on an account.", fields: [
        { name: "account", label: "Account", placeholder: "RAIDACCOUNT", required: true },
        { name: "mode", label: "Mode", type: "select", options: [{ value: "dry", label: "Dry Run" }, { value: "sell", label: "Sell Items" }], required: true },
        { name: "maxQuality", label: "Max Quality", type: "select", options: [{ value: "3", label: "Blue and below" }, { value: "2", label: "Green only" }], required: true }
      ] }
    ]
  },
  {
    id: "raids",
    title: "Raids",
    subtitle: "Private-server raid resets and readiness",
    tools: [
      { action: "queueAvRaid", label: "Queue AV Raid", description: "Queue an online raid for Alterac Valley using the AzerothCore server-side queue helper.", fields: [
        { name: "character", label: "Raid Leader", placeholder: "Charactername", required: true }
      ] },
      { action: "raidLockoutReset", label: "Raid Lockouts", description: "Preview or remove raid lockouts for a character, account, or all characters.", fields: [
        { name: "mode", label: "Mode", type: "select", options: [{ value: "preview", label: "Preview Only" }, { value: "reset", label: "Reset Lockouts" }], required: true },
        { name: "raid", label: "Raid", type: "select", options: Object.entries(raidLockoutTargets).map(([value, target]) => ({ value, label: target.label })), required: true },
        { name: "scope", label: "Scope", type: "select", options: [{ value: "character", label: "Character" }, { value: "account", label: "Account" }, { value: "all", label: "All Characters" }], required: true },
        { name: "character", label: "Character", placeholder: "Charactername" },
        { name: "account", label: "Account", placeholder: "ACCOUNT" }
      ] }
    ]
  },
  {
    id: "auction-house",
    title: "Auction House",
    subtitle: "AHBot visibility and restock helpers",
    tools: [
      { action: "ahStatus", label: "AHBot Status", description: "Show auction bot status.", fields: [] },
      { action: "ahReload", label: "Reload AHBot", description: "Reload AHBot settings.", fields: [] },
      { action: "ahRestockRange", label: "Check Level Range", description: "Review auction depth for a level range.", fields: [{ name: "minLevel", label: "Min", type: "number", placeholder: "50", min: "1", max: "80", required: true }, { name: "maxLevel", label: "Max", type: "number", placeholder: "65", min: "1", max: "80", required: true }] }
    ]
  },
  {
    id: "accounts",
    title: "Accounts",
    subtitle: "Common account administration",
    tools: [
      { action: "accountCreate", label: "Create Account", description: "Create a new game account.", fields: [{ name: "account", label: "Account", placeholder: "account2", required: true }, { name: "password", label: "Password", type: "password", placeholder: "Password", required: true }] },
      { action: "accountPassword", label: "Set Password", description: "Change an account password.", fields: [{ name: "account", label: "Account", placeholder: "account2", required: true }, { name: "password", label: "Password", type: "password", placeholder: "Password", required: true }] },
      { action: "accountGm", label: "Set GM Level", description: "Set account GM level.", fields: [{ name: "account", label: "Account", placeholder: "SOAP_ADMIN", required: true }, { name: "level", label: "GM", type: "select", options: ["0", "1", "2", "3"], required: true }] }
    ]
  },
  {
    id: "lookup",
    title: "Lookup",
    subtitle: "Find game data without leaving the portal",
    tools: [
      { action: "lookupItem", label: "Lookup Item", description: "Search item templates.", fields: [{ name: "term", label: "Item", placeholder: "Arcanite", required: true }] },
      { action: "lookupCreature", label: "Lookup Creature", description: "Search creature templates.", fields: [{ name: "term", label: "Creature", placeholder: "Ragnaros", required: true }] },
      { action: "lookupQuest", label: "Lookup Quest", description: "Search quests.", fields: [{ name: "term", label: "Quest", placeholder: "Molten Core", required: true }] }
    ]
  }
];

const advisorReports = {
  health: {
    label: "Server Health",
    description: "Summarize realm health from portal metrics and identify only issues that need action.",
    task: "Assess AzerothCore server health from the supplied portal snapshot and Portal knowledge profile. State whether action is needed. Keep it practical for the administrator. Do not propose shell, SQL, SOAP, service restarts, or GM commands unless a curated admin action fits exactly."
  },
  auctionHouse: {
    label: "Auction House",
    description: "Review AH depth and point out gaps worth checking.",
    task: "Assess the AzerothCore auction house from the supplied portal snapshot and Portal knowledge profile. Focus on practical stock gaps, level ranges, and whether a curated AH action is useful. Preserve a Blizzlike economy and do not change AH settings directly."
  },
  bags: {
    label: "Bag Cleanup",
    description: "Plan what facts are needed to help with full bot bags.",
    task: "Act as the bag cleanup advisor for AzerothCore playerbots. Use supplied character facts when available. Identify vendor trash, soulbound unequipped gear, free bag space, and whether a repair bot action would help. Do not alter Playerbot combat, party, dungeon, raid, rotation, or strategy behavior."
  },
  repair: {
    label: "Repair Bot",
    description: "Check repair-bot readiness and missing facts.",
    task: "Act as the repair bot advisor for AzerothCore. If the administrator names an online character, prefer the curated Summon Repair Bot action. If no character is named, ask which character should receive the bot. The portal action uses .portaltools repairbot and is allowed in dungeons and battlegrounds."
  },
  dungeon: {
    label: "Dungeon Readiness",
    description: "Prepare a practical readiness report for a run.",
    task: "Create a AzerothCore dungeon or raid readiness plan from the supplied portal snapshot, Portal knowledge profile, and any character facts. Identify missing roster, role, gear, consumable, durability, bag, and travel facts. Do not alter Playerbot combat, party, dungeon, raid, rotation, or strategy behavior."
  },
  flavor: {
    label: "Static Flavor Text",
    description: "Plan safe static text expansion for playerbot chatter.",
    task: "Plan static Playerbot flavor text expansion for AzerothCore. Keep this offline/static: generated chunks can be reviewed and stored, but do not propose live LLM chat behavior or changes to Playerbot gameplay logic."
  },
  playerbots: {
    label: "Playerbot Care",
    description: "Maintenance and safety checks for bots.",
    task: "Act as the AzerothCore Playerbot care advisor. Treat current party and raid behavior as protected. Prefer curated maintenance, reset, summon, dismiss, character facts, and bag/repair recommendations. Do not propose strategy, rotation, combat, party, or raid behavior changes unless the administrator explicitly asks."
  },
  modules: {
    label: "Modules & Updates",
    description: "Plan module updates or new QoL additions safely.",
    task: "Act as the AzerothCore module/update planning advisor. Use the Portal knowledge profile and admin catalog. Recommend a staged plan with backup, build, verification, and rollback steps. Do not propose immediate updates unless the request clearly asks to update."
  }
};

const adminActionCatalog = adminToolGroups.flatMap(group =>
  group.tools.map(tool => ({
    group: group.title,
    action: tool.action,
    label: tool.label,
    description: tool.description,
    fields: tool.fields.map(field => ({
      name: field.name,
      label: field.label,
      required: Boolean(field.required),
      type: field.type || "text",
      options: (field.options || []).map(option => typeof option === "object" ? option.value : option)
    }))
  }))
);

const adminActionMap = new Map(adminActionCatalog.map(action => [action.action, action]));

function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.redirect("/login");
  if (!user.isAdmin) {
    return res.status(403).send(layout({
      title: "Admin Access",
      body: `<section class="page-head"><h1>Admin Access</h1><a class="button ghost back-button" href="/"><span>Back</span></a></section>
        <article class="panel"><p class="muted">This portal account is not marked as an administrator.</p></article>`,
      user
    }));
  }

  req.portalUser = user;
  return next();
}

function requireUser(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.redirect("/login");
  req.portalUser = user;
  return next();
}

function downloadHeaders(fileSize, fileName = clientDownloadName) {
  const asciiName = fileName.replace(/[^\x20-\x7E]/g, "").replaceAll('"', "");
  return {
    "Accept-Ranges": "bytes",
    "Content-Type": "application/zip",
    "Content-Disposition": `attachment; filename="${asciiName}"; filename*=UTF-8''${encodeURIComponent(fileName)}`,
    "Cache-Control": "private, no-store",
    "Content-Length": String(fileSize)
  };
}

function parseRangeHeader(rangeHeader, fileSize) {
  const match = String(rangeHeader || "").match(/^bytes=(\d*)-(\d*)$/);
  if (!match) return null;
  const [, startValue, endValue] = match;
  if (!startValue && !endValue) return null;

  if (!startValue) {
    const suffixLength = Number(endValue);
    if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) return null;
    const start = Math.max(fileSize - suffixLength, 0);
    return { start, end: fileSize - 1 };
  }

  const start = Number(startValue);
  const end = endValue ? Number(endValue) : fileSize - 1;
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end || start >= fileSize) return null;
  return { start, end: Math.min(end, fileSize - 1) };
}

async function query(sql, params = {}) {
  const [rows] = await db.query(sql, params);
  return rows;
}

async function scalar(sql, params = {}) {
  const rows = await query(sql, params);
  return Number(Object.values(rows[0] || { value: 0 })[0] || 0);
}

async function ensurePortalTables() {
  await query(`CREATE TABLE IF NOT EXISTS acore_auth.portal_users (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    account_id INT UNSIGNED NOT NULL,
    username VARCHAR(32) NOT NULL,
    email VARCHAR(255) NOT NULL DEFAULT '',
    password_salt VARCHAR(64) NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    is_admin TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_portal_users_account (account_id),
    UNIQUE KEY uq_portal_users_username (username)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  try {
    await query("ALTER TABLE acore_auth.portal_users ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0 AFTER password_hash");
  } catch (error) {
    if (error.code !== "ER_DUP_FIELDNAME") throw error;
  }

  await query(`CREATE TABLE IF NOT EXISTS acore_auth.portal_launcher_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    account_id INT UNSIGNED NOT NULL,
    token_hash CHAR(64) NOT NULL,
    token_prefix VARCHAR(16) NOT NULL,
    device_name VARCHAR(80) NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP NULL DEFAULT NULL,
    revoked_at TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_portal_launcher_tokens_hash (token_hash),
    KEY idx_portal_launcher_tokens_account (account_id),
    KEY idx_portal_launcher_tokens_expires (expires_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await query(`CREATE TABLE IF NOT EXISTS acore_auth.portal_raid_runs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    source_run_id VARCHAR(96) NOT NULL,
    uploader_account_id INT UNSIGNED NOT NULL,
    instance_name VARCHAR(96) NOT NULL,
    map_id INT UNSIGNED NOT NULL DEFAULT 0,
    difficulty VARCHAR(32) NOT NULL DEFAULT '',
    started_at DATETIME NULL DEFAULT NULL,
    ended_at DATETIME NULL DEFAULT NULL,
    note VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_portal_raid_runs_source (source_run_id),
    KEY idx_portal_raid_runs_instance (instance_name, started_at),
    KEY idx_portal_raid_runs_uploader (uploader_account_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await query(`CREATE TABLE IF NOT EXISTS acore_auth.portal_raid_boss_kills (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    run_id BIGINT UNSIGNED NOT NULL,
    source_boss_id VARCHAR(96) NOT NULL,
    boss_name VARCHAR(96) NOT NULL,
    boss_entry INT UNSIGNED NOT NULL DEFAULT 0,
    encounter_id INT UNSIGNED NOT NULL DEFAULT 0,
    killed_at DATETIME NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_portal_raid_boss_source (run_id, source_boss_id),
    KEY idx_portal_raid_boss_run (run_id),
    KEY idx_portal_raid_boss_name (boss_name)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await query(`CREATE TABLE IF NOT EXISTS acore_auth.portal_raid_loot_drops (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    run_id BIGINT UNSIGNED NOT NULL,
    boss_id BIGINT UNSIGNED NULL DEFAULT NULL,
    event_id VARCHAR(128) NOT NULL,
    uploader_account_id INT UNSIGNED NOT NULL,
    recipient_guid INT UNSIGNED NULL DEFAULT NULL,
    recipient_name VARCHAR(32) NOT NULL,
    item_entry INT UNSIGNED NOT NULL,
    item_name VARCHAR(128) NOT NULL,
    item_link TEXT NOT NULL,
    quality TINYINT UNSIGNED NOT NULL,
    quantity INT UNSIGNED NOT NULL DEFAULT 1,
    looted_at DATETIME NULL DEFAULT NULL,
    raw_json TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_portal_raid_loot_event (event_id),
    KEY idx_portal_raid_loot_run (run_id),
    KEY idx_portal_raid_loot_boss (boss_id),
    KEY idx_portal_raid_loot_recipient (recipient_name),
    KEY idx_portal_raid_loot_item (item_entry),
    KEY idx_portal_raid_loot_quality (quality)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
}

async function ensureAdminActionHistoryTable() {
  await query(`CREATE TABLE IF NOT EXISTS acore_auth.portal_admin_action_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(32) NOT NULL,
    action_key VARCHAR(64) NOT NULL,
    action_label VARCHAR(128) NOT NULL,
    params_text TEXT NOT NULL,
    status VARCHAR(128) NOT NULL,
    success TINYINT(1) NOT NULL DEFAULT 0,
    output_excerpt TEXT NOT NULL,
    PRIMARY KEY (id),
    KEY idx_portal_admin_action_history_created (created_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
}

async function getEquippedGear(guids) {
  if (!guids.length) return new Map();

  const placeholders = guids.map(() => "?").join(",");
  const [rows] = await db.query(`SELECT
      ci.guid,
      ci.slot,
      ii.itemEntry entry,
      it.name,
      it.Quality quality,
      it.ItemLevel itemLevel,
      it.RequiredLevel requiredLevel,
      it.InventoryType inventoryType,
      it.class itemClass,
      it.subclass itemSubclass,
      it.itemset itemSet
    FROM acore_characters.character_inventory ci
    JOIN acore_characters.item_instance ii ON ii.guid = ci.item
    JOIN acore_world.item_template it ON it.entry = ii.itemEntry
    WHERE ci.bag = 0
      AND ci.slot BETWEEN 0 AND 18
      AND ci.guid IN (${placeholders})
    ORDER BY ci.guid, ci.slot`, guids);

  const itemSetIds = [...new Set(rows.map(row => Number(row.itemSet || 0)).filter(id => id > 0))];
  const itemSetInfoById = new Map();
  if (itemSetIds.length) {
    const setPlaceholders = itemSetIds.map(() => "?").join(",");
    const [setRows] = await db.query(`SELECT
        ID id,
        Name_Lang_enUS name,
        SetSpellID_1, SetSpellID_2, SetSpellID_3, SetSpellID_4,
        SetSpellID_5, SetSpellID_6, SetSpellID_7, SetSpellID_8,
        SetThreshold_1, SetThreshold_2, SetThreshold_3, SetThreshold_4,
        SetThreshold_5, SetThreshold_6, SetThreshold_7, SetThreshold_8
      FROM acore_world.itemset_dbc
      WHERE ID IN (${setPlaceholders})`, itemSetIds);

    const spellIds = [...new Set(setRows.flatMap(row => Array.from({ length: 8 }, (_, index) => Number(row[`SetSpellID_${index + 1}`] || 0))).filter(id => id > 0))];
    const spellInfoById = new Map();
    if (spellIds.length) {
      const spellPlaceholders = spellIds.map(() => "?").join(",");
      const [spellRows] = await db.query(`SELECT ID id, Name_Lang_enUS name, Description_Lang_enUS description
        FROM acore_world.spell_dbc
        WHERE ID IN (${spellPlaceholders})`, spellIds);
      for (const spell of spellRows) {
        spellInfoById.set(Number(spell.id), {
          id: Number(spell.id),
          name: spell.name || `Spell ${Number(spell.id)}`,
          description: String(spell.description || "").replace(/\s+/g, " ").trim()
        });
      }
    }

    for (const setRow of setRows) {
      const bonuses = [];
      for (let index = 1; index <= 8; index += 1) {
        const spellId = Number(setRow[`SetSpellID_${index}`] || 0);
        const threshold = Number(setRow[`SetThreshold_${index}`] || 0);
        if (!spellId || !threshold) continue;
        const spell = spellInfoById.get(spellId) || { id: spellId, name: `Spell ${spellId}`, description: "" };
        bonuses.push({ threshold, spellId, name: spell.name, description: spell.description });
      }
      itemSetInfoById.set(Number(setRow.id), {
        id: Number(setRow.id),
        name: setRow.name || `Item Set ${Number(setRow.id)}`,
        bonuses
      });
    }

    const missingSetIds = itemSetIds.filter(id => !itemSetInfoById.has(id));
    if (missingSetIds.length) {
      const missingPlaceholders = missingSetIds.map(() => "?").join(",");
      const [fallbackRows] = await db.query(`SELECT itemset, entry, name
        FROM acore_world.item_template
        WHERE itemset IN (${missingPlaceholders})
        ORDER BY itemset, entry`, missingSetIds);
      const namesBySetId = new Map();
      for (const row of fallbackRows) {
        const setId = Number(row.itemset || 0);
        if (!namesBySetId.has(setId)) namesBySetId.set(setId, []);
        namesBySetId.get(setId).push(row.name || `Item ${Number(row.entry)}`);
      }
      for (const setId of missingSetIds) {
        const known = itemSetFallbacks[setId];
        const names = namesBySetId.get(setId) || [];
        itemSetInfoById.set(setId, {
          id: setId,
          name: known?.name || deriveSetNameFromItems(names, setId),
          bonuses: known?.bonuses || fallbackBonusesForPieceCount(names.length)
        });
      }
    }
  }

  const gearByGuid = new Map();
  for (const row of rows) {
    const key = Number(row.guid);
    const setId = Number(row.itemSet || 0);
    if (setId > 0) row.itemSetInfo = itemSetInfoById.get(setId) || null;
    if (!gearByGuid.has(key)) gearByGuid.set(key, new Map());
    gearByGuid.get(key).set(Number(row.slot), row);
  }

  return gearByGuid;
}

async function getCharacterSpecs(rows) {
  const characters = (rows || [])
    .map(row => ({
      guid: Number(row.guid),
      classId: Number(row.class),
      activeTalentGroup: Number(row.activeTalentGroup || 0)
    }))
    .filter(row => Number.isFinite(row.guid));
  if (!characters.length) return new Map();

  const activeGroupByGuid = new Map(characters.map(row => [row.guid, row.activeTalentGroup]));
  const classByGuid = new Map(characters.map(row => [row.guid, row.classId]));
  const ids = characters.map(row => row.guid);
  const placeholders = ids.map(() => "?").join(",");
  const [talentRows] = await db.query(`SELECT guid, spell, specMask
    FROM acore_characters.character_talent
    WHERE guid IN (${placeholders})`, ids);

  const spellsByGuid = new Map();
  for (const row of talentRows) {
    const guid = Number(row.guid);
    const activeMask = 1 << Number(activeGroupByGuid.get(guid) || 0);
    if ((Number(row.specMask || 0) & activeMask) === 0) continue;
    if (!spellsByGuid.has(guid)) spellsByGuid.set(guid, new Set());
    spellsByGuid.get(guid).add(Number(row.spell));
  }

  const specsByGuid = new Map();
  for (const character of characters) {
    const signatures = specSignatures[classByGuid.get(character.guid)] || [];
    const spells = spellsByGuid.get(character.guid) || new Set();
    let best = null;

    for (const signature of signatures) {
      const score = signature.spells.reduce((sum, spell) => sum + (spells.has(spell) ? 1 : 0), 0);
      if (!best || score > best.score) best = { name: signature.name, score };
    }

    specsByGuid.set(character.guid, best && best.score > 0 ? best.name : "No Spec");
  }

  return specsByGuid;
}

function inventoryLocation(row) {
  const bag = Number(row.bag);
  const slot = Number(row.slot);
  if (bag !== 0) return `Bag ${bag} slot ${slot}`;
  if (slot <= 18) return "Equipped";
  if (slot >= 19 && slot <= 22) return "Equipped bag";
  if (slot >= 23 && slot <= 38) return "Backpack";
  if (slot >= 39 && slot <= 66) return "Bank";
  if (slot >= 67 && slot <= 74) return "Bank bag";
  if (slot >= 74 && slot <= 85) return "Buyback";
  if (slot >= 86 && slot <= 117) return "Keyring";
  return `Slot ${slot}`;
}

function advisorCharacterSearchParts(task) {
  const text = String(task || "");
  const names = [...new Set(text
    .toLowerCase()
    .match(/\b[a-z][a-z0-9]{2,23}\b/g) || [])]
    .filter(word => !new Set([
      "the", "and", "for", "with", "current", "state", "inventory", "character",
      "lookup", "look", "check", "show", "tell", "give", "what", "does", "have",
      "guid", "admin", "advisor", "please", "items", "bags", "bag"
    ]).has(word))
    .slice(0, 20);
  const guids = [...new Set([...text.matchAll(/\bguid\s*[:#]?\s*(\d{1,10})\b/gi)].map(match => Number(match[1])))]
    .filter(Number.isSafeInteger)
    .slice(0, 5);
  return { names, guids };
}

async function getAdvisorCharacterFacts(task) {
  const { names, guids } = advisorCharacterSearchParts(task);
  if (!names.length && !guids.length) return [];

  const clauses = [];
  const params = [];
  if (names.length) {
    clauses.push(`LOWER(c.name) IN (${names.map(() => "?").join(",")})`);
    params.push(...names);
  }
  if (guids.length) {
    clauses.push(`c.guid IN (${guids.map(() => "?").join(",")})`);
    params.push(...guids);
  }

  const [characters] = await db.query(`SELECT c.guid, c.name, c.level, c.race, c.class, c.online, c.map,
      c.position_x positionX, c.position_y positionY, c.position_z positionZ,
      a.username account
    FROM acore_characters.characters c
    JOIN acore_auth.account a ON a.id = c.account
    WHERE ${clauses.join(" OR ")}
    ORDER BY c.name
    LIMIT 5`, params);

  if (!characters.length) return [];
  const characterGuids = characters.map(character => Number(character.guid));
  const placeholders = characterGuids.map(() => "?").join(",");
  const [inventoryRows] = await db.query(`SELECT
      ci.guid,
      ci.bag,
      ci.slot,
      ci.item itemGuid,
      ii.itemEntry entry,
      ii.count,
      ii.flags,
      ii.durability,
      it.name,
      it.Quality quality,
      it.ItemLevel itemLevel,
      it.RequiredLevel requiredLevel,
      it.class itemClass,
      it.subclass itemSubclass,
      it.InventoryType inventoryType,
      it.ContainerSlots containerSlots,
      it.MaxDurability maxDurability
    FROM acore_characters.character_inventory ci
    JOIN acore_characters.item_instance ii ON ii.guid = ci.item
    JOIN acore_world.item_template it ON it.entry = ii.itemEntry
    WHERE ci.guid IN (${placeholders})
    ORDER BY ci.guid, ci.bag, ci.slot
    LIMIT 500`, characterGuids);

  const rowsByGuid = new Map();
  for (const row of inventoryRows) {
    const guid = Number(row.guid);
    if (!rowsByGuid.has(guid)) rowsByGuid.set(guid, []);
    rowsByGuid.get(guid).push(row);
  }

  return characters.map(character => {
    const guid = Number(character.guid);
    const rows = rowsByGuid.get(guid) || [];
    const equippedBags = rows
      .filter(row => Number(row.bag) === 0 && Number(row.slot) >= 19 && Number(row.slot) <= 22)
      .map(row => ({ itemGuid: Number(row.itemGuid), name: row.name, slots: Number(row.containerSlots || 0) }));
    const usedByBag = new Map();
    for (const row of rows) {
      const bag = Number(row.bag);
      if (bag !== 0) usedByBag.set(bag, (usedByBag.get(bag) || 0) + 1);
    }
    const backpackUsed = rows.filter(row => Number(row.bag) === 0 && Number(row.slot) >= 23 && Number(row.slot) <= 38).length;

    return {
      guid,
      name: character.name,
      account: character.account,
      level: Number(character.level),
      race: Number(character.race),
      class: Number(character.class),
      online: Boolean(Number(character.online)),
      map: Number(character.map),
      position: {
        x: Number(character.positionX),
        y: Number(character.positionY),
        z: Number(character.positionZ)
      },
      inventorySummary: {
        totalRows: rows.length,
        backpackUsed,
        backpackFree: Math.max(16 - backpackUsed, 0),
        equippedBags: equippedBags.map(bag => ({
          name: bag.name,
          slots: bag.slots,
          used: usedByBag.get(bag.itemGuid) || 0,
          free: Math.max(bag.slots - (usedByBag.get(bag.itemGuid) || 0), 0)
        }))
      },
      inventory: rows.map(row => ({
        location: inventoryLocation(row),
        bag: Number(row.bag),
        slot: Number(row.slot),
        itemGuid: Number(row.itemGuid),
        entry: Number(row.entry),
        name: row.name,
        count: Number(row.count),
        quality: Number(row.quality),
        itemLevel: Number(row.itemLevel),
        requiredLevel: Number(row.requiredLevel),
        itemClass: Number(row.itemClass),
        itemSubclass: Number(row.itemSubclass),
        inventoryType: Number(row.inventoryType),
        flags: Number(row.flags),
        soulbound: Boolean(Number(row.flags) & 1),
        durability: Number(row.durability),
        maxDurability: Number(row.maxDurability)
      }))
    };
  });
}

function textParam(body, name, label = name) {
  const value = String(body[name] || "").trim();
  if (!value) throw new Error(`${label} is required.`);
  if (/[<>"'`;|&]/.test(value)) throw new Error(`${label} contains unsupported characters.`);
  return value;
}

function optionalTextParam(body, name, fallback = "") {
  const value = String(body[name] || "").trim();
  if (!value) return fallback;
  if (/[<>"'`;|&]/.test(value)) throw new Error(`${name} contains unsupported characters.`);
  return value;
}

function numberParam(body, name, label = name, min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER) {
  const value = Number(String(body[name] || "").trim());
  if (!Number.isInteger(value)) throw new Error(`${label} must be a whole number.`);
  if (value < min || value > max) throw new Error(`${label} must be between ${min} and ${max}.`);
  return value;
}

function buildAdminCommand(actionKey, body) {
  const staticAction = soapActions[actionKey];
  if (staticAction) return { label: staticAction.label, command: staticAction.command(body) };

  switch (actionKey) {
    case "announce":
      return { label: "Announce", command: `announce ${textParam(body, "message", "Message")}` };
    case "restartWarning": {
      const minutes = numberParam(body, "minutes", "Minutes", 1, 60);
      return { label: "Restart Warning", command: `announce Server restart in ${minutes} minute${minutes === 1 ? "" : "s"}. Please find a safe spot.` };
    }
    case "pinfo":
      return { label: "Character Info", command: `pinfo ${textParam(body, "character", "Character")}` };
    case "revive":
      return { label: "Revive", command: `revive ${textParam(body, "character", "Character")}` };
    case "unstuck":
      return { label: "Unstuck to Inn", command: `unstuck ${textParam(body, "character", "Character")} inn` };
    case "summon":
      return { label: "Summon to GM", command: `summon ${textParam(body, "character", "Character")}` };
    case "summonToCharacter":
      return { label: "Summon to Raid Member", command: `portaltools summonto ${textParam(body, "character", "Character to Move")} ${textParam(body, "destination", "Destination Character")}` };
    case "appear":
      return { label: "Go to Character", command: `appear ${textParam(body, "character", "Character")}` };
    case "rename":
      return { label: "Flag Rename", command: `character rename ${textParam(body, "character", "Character")}` };
    case "level":
      return { label: "Set Level", command: `character level ${textParam(body, "character", "Character")} ${numberParam(body, "level", "Level", 1, 80)}` };
    case "addItem": {
      const count = numberParam({ count: optionalTextParam(body, "count", "1") }, "count", "Count", 1, 200);
      const character = textParam(body, "character", "Character");
      const entry = numberParam(body, "entry", "Item ID", 1);
      const delivery = optionalTextParam(body, "delivery", "mail");
      if (!["mail", "direct"].includes(delivery)) throw new Error("Delivery must be Mail or Direct Bag.");
      if (delivery === "direct") {
        return { label: "Grant Item", command: `additem ${character} ${entry} ${count}` };
      }
      return { label: "Grant Item", command: `send items ${character} "AzerothCore Item Grant" "Granted from the AzerothCore portal." ${entry}:${count}` };
    }
    case "learnSpell":
      return { label: "Learn Spell", command: `learn ${textParam(body, "character", "Character")} ${numberParam(body, "spell", "Spell ID", 1)}` };
    case "resetTalents":
      return { label: "Reset Talents", command: `reset talents ${textParam(body, "character", "Character")}` };
    case "repair":
      return { label: "Repair Gear", command: `repairitems ${textParam(body, "character", "Character")}` };
    case "summonRepairBot": {
      const duration = numberParam({ duration: optionalTextParam(body, "duration", "10") }, "duration", "Minutes", 1, 30);
      const entry = numberParam({ entry: optionalTextParam(body, "entry", "24780") }, "entry", "Bot", 1);
      return { label: "Summon Repair Bot", command: `portaltools repairbot ${textParam(body, "character", "Character")} ${duration} ${entry}` };
    }
    case "queueAvRaid":
      return { label: "Queue AV Raid", command: `portaltools queueav ${textParam(body, "character", "Raid Leader")}` };
    case "setTitle":
      return { label: "Set Title", command: `titles set ${textParam(body, "character", "Character")} ${numberParam(body, "title", "Title", 1)}` };
    case "botMaintenance":
      return { label: "Bot Maintenance", command: `playerbot maintenance ${textParam(body, "character", "Bot")}` };
    case "botReset":
      return { label: "Reset Bot AI", command: `playerbot reset ${textParam(body, "character", "Bot")}` };
    case "botSummon":
      return { label: "Summon Bot", command: `playerbot summon ${textParam(body, "character", "Bot")}` };
    case "botDismiss":
      return { label: "Dismiss Bot", command: `playerbot dismiss ${textParam(body, "character", "Bot")}` };
    case "ahStatus":
      return { label: "AHBot Status", command: "" };
    case "ahReload":
      return { label: "Reload Auctions", command: "reload auctions" };
    case "accountCreate":
      return { label: "Create Account", command: `account create ${textParam(body, "account", "Account")} ${textParam(body, "password", "Password")}` };
    case "accountPassword":
      return { label: "Set Password", command: `account set password ${textParam(body, "account", "Account")} ${textParam(body, "password", "Password")} ${textParam(body, "password", "Password")}` };
    case "accountGm":
      return { label: "Set GM Level", command: `account set gmlevel ${textParam(body, "account", "Account")} ${numberParam(body, "level", "GM level", 0, 3)} -1` };
    case "lookupItem":
      return { label: "Lookup Item", command: `lookup item ${textParam(body, "term", "Item")}` };
    case "lookupCreature":
      return { label: "Lookup Creature", command: `lookup creature ${textParam(body, "term", "Creature")}` };
    case "lookupQuest":
      return { label: "Lookup Quest", command: `lookup quest ${textParam(body, "term", "Quest")}` };
    default:
      throw new Error("Unknown or unsupported server action.");
  }
}

async function soapCommand(command) {
  const user = process.env.SOAP_USER || "SOAP_ADMIN";
  const pass = process.env.SOAP_PASSWORD || "";
  const host = process.env.SOAP_HOST || "127.0.0.1";
  const soapPort = process.env.SOAP_PORT || "7878";
  const auth = Buffer.from(`${user}:${pass}`).toString("base64");
  const envelope = `<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:AC">
  <SOAP-ENV:Body>
    <ns1:executeCommand>
      <command>${escapeHtml(command)}</command>
    </ns1:executeCommand>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`;

  const response = await fetch(`http://${host}:${soapPort}/`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "text/xml"
    },
    body: envelope
  });

  return response.text();
}

function adminActionParamsForLog(actionKey, body) {
  const tool = adminActionMap.get(actionKey);
  if (!tool) return {};
  return Object.fromEntries(tool.fields.map(field => {
    const value = String(body[field.name] || "");
    return [field.name, field.type === "password" ? "[redacted]" : value];
  }));
}

async function logAdminAction({ source, actionKey, label, params, status, success, output }) {
  try {
    await ensureAdminActionHistoryTable();
    await query(`INSERT INTO acore_auth.portal_admin_action_history
      (source, action_key, action_label, params_text, status, success, output_excerpt)
      VALUES (:source, :actionKey, :label, :paramsText, :status, :success, :output)`, {
      source,
      actionKey,
      label,
      paramsText: JSON.stringify(params || {}),
      status,
      success: success ? 1 : 0,
      output: String(output || "").slice(0, 2000)
    });
  } catch (error) {
    console.error("Failed to log admin action", error);
  }
}

async function getAdminActionHistory(limit = 12) {
  try {
    await ensureAdminActionHistoryTable();
    return await query(`SELECT id, created_at createdAt, source, action_key actionKey,
        action_label actionLabel, params_text paramsText, status, success
      FROM acore_auth.portal_admin_action_history
      ORDER BY id DESC
      LIMIT :limit`, { limit });
  } catch (error) {
    console.error("Failed to read admin action history", error);
    return [];
  }
}

function formatCopper(copper) {
  const value = Number(copper || 0);
  const gold = Math.floor(value / 10000);
  const silver = Math.floor((value % 10000) / 100);
  const copperOnly = value % 100;
  return `${gold}g ${silver}s ${copperOnly}c`;
}

async function getRaidBagCleanupCandidates(accountName, maxQuality) {
  return await query(`SELECT
      c.guid characterGuid,
      c.name characterName,
      c.online,
      ci.item itemGuid,
      ci.bag,
      ci.slot,
      ii.itemEntry entry,
      ii.count itemCount,
      ii.flags,
      it.name itemName,
      it.Quality quality,
      it.ItemLevel itemLevel,
      it.RequiredLevel requiredLevel,
      it.class itemClass,
      it.subclass itemSubclass,
      it.SellPrice sellPrice,
      (it.SellPrice * ii.count) vendorValue
    FROM acore_auth.account a
    JOIN acore_characters.characters c ON c.account = a.id
    JOIN acore_characters.character_inventory ci ON ci.guid = c.guid
    JOIN acore_characters.item_instance ii ON ii.guid = ci.item
    JOIN acore_world.item_template it ON it.entry = ii.itemEntry
    WHERE a.username = :account
      AND c.online = 0
      AND (ii.flags & 1) = 1
      AND it.Quality BETWEEN 2 AND :maxQuality
      AND it.class IN (2, 4)
      AND it.SellPrice > 0
      AND (
        (ci.bag = 0 AND ci.slot BETWEEN 23 AND 38)
        OR ci.bag IN (
          SELECT bagci.item
          FROM acore_characters.character_inventory bagci
          WHERE bagci.guid = c.guid
            AND bagci.bag = 0
            AND bagci.slot BETWEEN 19 AND 22
        )
      )
    ORDER BY c.name, it.Quality DESC, it.ItemLevel DESC, it.name`, {
    account: accountName,
    maxQuality
  });
}

function renderRaidBagCleanupOutput({ accountName, mode, maxQuality, rows, onlineRows = [], sold = false }) {
  const totalValue = rows.reduce((sum, row) => sum + Number(row.vendorValue || 0), 0);
  const byCharacter = new Map();
  for (const row of rows) {
    if (!byCharacter.has(row.characterName)) byCharacter.set(row.characterName, []);
    byCharacter.get(row.characterName).push(row);
  }

  return `<div class="command-output raid-cleanup-output" role="log">
    <div class="command-output-row"><span class="output-label">Account</span><span class="output-value">${escapeHtml(accountName)}</span></div>
    <div class="command-output-row"><span class="output-label">Mode</span><span class="output-value">${escapeHtml(mode === "sell" ? "Sell Items" : "Dry Run")}</span></div>
    <div class="command-output-row"><span class="output-label">Scope</span><span class="output-value">Offline characters only, carried bags only, soulbound ${Number(maxQuality) >= 3 ? "green/blue" : "green"} armor and weapons.</span></div>
    <div class="command-output-row"><span class="output-label">Matched Items</span><span class="output-value">${rows.length}</span></div>
    <div class="command-output-row"><span class="output-label">${sold ? "Credited" : "Potential Value"}</span><span class="output-value">${escapeHtml(formatCopper(totalValue))}</span></div>
    ${onlineRows.length ? `<div class="command-output-line">Skipped online characters: ${onlineRows.map(row => escapeHtml(row.name)).join(", ")}</div>` : ""}
    ${rows.length ? [...byCharacter.entries()].map(([name, items]) => `<div class="command-output-line"><strong>${escapeHtml(name)}</strong> - ${items.length} item${items.length === 1 ? "" : "s"} - ${escapeHtml(formatCopper(items.reduce((sum, row) => sum + Number(row.vendorValue || 0), 0)))}</div>
      ${items.slice(0, 30).map(row => `<div class="command-output-row"><span class="output-label">${renderWowheadItemLink({ entry: row.entry, name: row.itemName, quality: row.quality })}</span><span class="output-value">Entry ${Number(row.entry)} - q${Number(row.quality)} - ilvl ${Number(row.itemLevel)} - ${escapeHtml(formatCopper(row.vendorValue))}</span></div>`).join("")}
      ${items.length > 30 ? `<div class="command-output-line">...${items.length - 30} more items for ${escapeHtml(name)}</div>` : ""}`).join("") : `<div class="command-output-line">No matching items found.</div>`}
  </div>`;
}

async function runRaidBagCleanup(body) {
  const accountName = textParam(body, "account", "Account").toUpperCase();
  const mode = optionalTextParam(body, "mode", "dry");
  if (!["dry", "sell"].includes(mode)) throw new Error("Mode must be dry or sell.");
  const maxQuality = numberParam({ maxQuality: optionalTextParam(body, "maxQuality", "3") }, "maxQuality", "Max Quality", 2, 3);

  const accounts = await query("SELECT id, username FROM acore_auth.account WHERE username = :account LIMIT 1", { account: accountName });
  if (!accounts.length) throw new Error(`Account ${accountName} was not found.`);

  const onlineRows = await query("SELECT name FROM acore_characters.characters WHERE account = :accountId AND online = 1 ORDER BY name", { accountId: accounts[0].id });
  const rows = await getRaidBagCleanupCandidates(accountName, maxQuality);

  if (mode === "dry" || !rows.length) {
    return renderRaidBagCleanupOutput({ accountName, mode, maxQuality, rows, onlineRows, sold: false });
  }

  if (onlineRows.length) {
    throw new Error(`Refusing to sell while account has online characters: ${onlineRows.map(row => row.name).join(", ")}`);
  }

  const itemGuids = [...new Set(rows.map(row => Number(row.itemGuid)))];
  const valuesByCharacter = new Map();
  for (const row of rows) {
    const guid = Number(row.characterGuid);
    valuesByCharacter.set(guid, (valuesByCharacter.get(guid) || 0) + Number(row.vendorValue || 0));
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    const itemPlaceholders = itemGuids.map(() => "?").join(",");
    await connection.query(`DELETE ci
      FROM acore_characters.character_inventory ci
      JOIN acore_characters.characters c ON c.guid = ci.guid
      WHERE ci.item IN (${itemPlaceholders})
        AND c.online = 0`, itemGuids);
    await connection.query(`DELETE ii
      FROM acore_characters.item_instance ii
      LEFT JOIN acore_characters.character_inventory ci ON ci.item = ii.guid
      WHERE ii.guid IN (${itemPlaceholders})
        AND ci.item IS NULL`, itemGuids);
    for (const [guid, value] of valuesByCharacter.entries()) {
      await connection.query("UPDATE acore_characters.characters SET money = money + ? WHERE guid = ? AND online = 0", [value, guid]);
    }
    await connection.commit();
  } catch (error) {
    try {
      await connection.rollback();
    } catch (rollbackError) {
      console.error("Raid bag cleanup rollback failed:", rollbackError);
    }
    throw error;
  } finally {
    connection.release();
  }

  return renderRaidBagCleanupOutput({ accountName, mode, maxQuality, rows, onlineRows, sold: true });
}

function raidLockoutTarget(body) {
  const raidKey = textParam(body, "raid", "Raid");
  const target = raidLockoutTargets[raidKey];
  if (!target) throw new Error("Choose a supported raid lockout target.");
  const mode = optionalTextParam(body, "mode", "preview");
  if (!["preview", "reset"].includes(mode)) throw new Error("Mode must be Preview Only or Reset Lockouts.");
  const scope = optionalTextParam(body, "scope", "character");
  if (!["character", "account", "all"].includes(scope)) throw new Error("Scope must be Character, Account, or All Characters.");
  const character = scope === "character" ? textParam(body, "character", "Character") : optionalTextParam(body, "character", "");
  const account = scope === "account" ? textParam(body, "account", "Account").toUpperCase() : optionalTextParam(body, "account", "").toUpperCase();
  return { raidKey, target, mode, scope, character, account };
}

function bindNumberList(prefix, values, params = {}) {
  const cleanValues = [...new Set(values.map(Number).filter(Number.isFinite))];
  if (!cleanValues.length) throw new Error(`${prefix} list cannot be empty.`);
  const names = cleanValues.map((value, index) => {
    const name = `${prefix}${index}`;
    params[name] = value;
    return `:${name}`;
  });
  return { sql: names.join(","), params, values: cleanValues };
}

function raidLockoutWhereClause({ target, scope, character, account }) {
  const maps = target.maps.map(Number).filter(Number.isFinite);
  if (!maps.length) throw new Error("Raid target has no maps.");
  const params = {};
  const mapBinding = bindNumberList("map", maps, params);
  let scopeSql = "";
  if (scope === "character") {
    params.character = character;
    scopeSql = "AND LOWER(c.name) = LOWER(:character)";
  } else if (scope === "account") {
    params.account = account;
    scopeSql = "AND UPPER(a.username) = :account";
  }
  return {
    mapSql: mapBinding.sql,
    scopeSql,
    params,
    maps: mapBinding.values
  };
}

async function getRaidLockoutRows(targetInfo) {
  const { mapSql, scopeSql, params } = raidLockoutWhereClause(targetInfo);
  const bindRows = await query(`SELECT
      ci.guid,
      c.name characterName,
      a.username accountName,
      a.id accountId,
      ci.instance,
      ci.permanent,
      ci.extended,
      i.map,
      i.difficulty,
      i.completedEncounters,
      i.resettime instanceReset,
      ir.resettime globalReset,
      COALESCE(NULLIF(i.resettime, 0), ir.resettime, 0) effectiveReset,
      'character' rowType
    FROM acore_characters.character_instance ci
    JOIN acore_characters.instance i ON i.id = ci.instance
    JOIN acore_characters.characters c ON c.guid = ci.guid
    JOIN acore_auth.account a ON a.id = c.account
    LEFT JOIN acore_characters.instance_reset ir ON ir.mapid = i.map AND ir.difficulty = i.difficulty
    WHERE i.map IN (${mapSql})
      ${scopeSql}
    ORDER BY i.map, a.username, c.name`, params);

  let timerSql;
  if (targetInfo.scope === "character") {
    timerSql = `SELECT DISTINCT
        c.guid,
        c.name characterName,
        a.username accountName,
        a.id accountId,
        ait.instanceId instance,
        0 permanent,
        0 extended,
        i.map,
        COALESCE(i.difficulty, 0) difficulty,
        COALESCE(i.completedEncounters, 0) completedEncounters,
        COALESCE(i.resettime, 0) instanceReset,
        COALESCE(ir.resettime, ait.releaseTime, 0) globalReset,
        COALESCE(NULLIF(i.resettime, 0), ait.releaseTime, ir.resettime, 0) effectiveReset,
        'account' rowType
      FROM acore_characters.account_instance_times ait
      JOIN acore_auth.account a ON a.id = ait.accountId
      JOIN acore_characters.characters c ON c.account = a.id
      LEFT JOIN acore_characters.instance i ON i.id = ait.instanceId
      LEFT JOIN acore_characters.instance_reset ir ON ir.mapid = i.map AND ir.difficulty = i.difficulty
      WHERE LOWER(c.name) = LOWER(:character)
        AND (i.map IN (${mapSql}) OR i.id IS NULL)
      ORDER BY a.username, c.name, ait.instanceId`;
  } else {
    const accountFilter = targetInfo.scope === "account" ? "AND UPPER(a.username) = :account" : "";
    timerSql = `SELECT
        0 guid,
        'Account timer' characterName,
        a.username accountName,
        a.id accountId,
        ait.instanceId instance,
        0 permanent,
        0 extended,
        i.map,
        COALESCE(i.difficulty, 0) difficulty,
        COALESCE(i.completedEncounters, 0) completedEncounters,
        COALESCE(i.resettime, 0) instanceReset,
        COALESCE(ir.resettime, ait.releaseTime, 0) globalReset,
        COALESCE(NULLIF(i.resettime, 0), ait.releaseTime, ir.resettime, 0) effectiveReset,
        'account' rowType
      FROM acore_characters.account_instance_times ait
      JOIN acore_auth.account a ON a.id = ait.accountId
      LEFT JOIN acore_characters.instance i ON i.id = ait.instanceId
      LEFT JOIN acore_characters.instance_reset ir ON ir.mapid = i.map AND ir.difficulty = i.difficulty
      WHERE (i.map IN (${mapSql}) OR i.id IS NULL)
        ${accountFilter}
      ORDER BY a.username, ait.instanceId`;
  }
  const timerRows = await query(timerSql, params);

  const seen = new Set();
  return [...bindRows, ...timerRows].filter(row => {
    const key = `${row.rowType}:${row.guid}:${row.accountId}:${row.instance}:${row.map || "orphan"}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function getRaidOnlineRows(targetInfo) {
  const { mapSql, scopeSql, params } = raidLockoutWhereClause(targetInfo);
  return await query(`SELECT c.name characterName, a.username accountName, c.map, c.instance_id instanceId
    FROM acore_characters.characters c
    JOIN acore_auth.account a ON a.id = c.account
    WHERE c.online = 1
      AND c.map IN (${mapSql})
      ${scopeSql}
    ORDER BY a.username, c.name
    LIMIT 50`, params);
}

async function getRaidScopeAccountIds(targetInfo) {
  if (targetInfo.scope === "all") return [];
  if (targetInfo.scope === "account") {
    const rows = await query(
      "SELECT id accountId FROM acore_auth.account WHERE UPPER(username) = :account LIMIT 1",
      { account: targetInfo.account }
    );
    return rows.map(row => Number(row.accountId)).filter(Number.isFinite);
  }

  const rows = await query(`SELECT DISTINCT a.id accountId
    FROM acore_characters.characters c
    JOIN acore_auth.account a ON a.id = c.account
    WHERE LOWER(c.name) = LOWER(:character)`, { character: targetInfo.character });
  return rows.map(row => Number(row.accountId)).filter(Number.isFinite);
}

async function getRaidRespawnRows(targetInfo, instanceIds = []) {
  const { mapSql, params } = raidLockoutWhereClause(targetInfo);
  const ids = [...new Set(instanceIds.map(Number).filter(Number.isFinite))];
  let instanceSql = "";
  if (targetInfo.scope !== "all") {
    if (!ids.length) return [];
    const instanceBinding = bindNumberList("respawnInstance", ids, params);
    instanceSql = `AND instanceId IN (${instanceBinding.sql})`;
  }

  const creatureRows = await query(`SELECT 'creature' rowType, mapId map, instanceId instance, COUNT(*) rowCount
    FROM acore_characters.creature_respawn
    WHERE mapId IN (${mapSql})
      ${instanceSql}
    GROUP BY mapId, instanceId`, params);
  const gameobjectRows = await query(`SELECT 'gameobject' rowType, mapId map, instanceId instance, COUNT(*) rowCount
    FROM acore_characters.gameobject_respawn
    WHERE mapId IN (${mapSql})
      ${instanceSql}
    GROUP BY mapId, instanceId`, params);
  return [...creatureRows, ...gameobjectRows];
}

function renderRaidLockoutOutput({ targetInfo, rows, respawnRows = [], reset = false, deletedRespawnRows = 0 }) {
  const byRaid = new Map();
  for (const row of rows) {
    const label = raidMapNames[Number(row.map)] || `Map ${Number(row.map)}`;
    if (!byRaid.has(label)) byRaid.set(label, []);
    byRaid.get(label).push(row);
  }
  const scopeLabel = targetInfo.scope === "all"
    ? "All Characters"
    : targetInfo.scope === "account"
      ? `Account ${targetInfo.account}`
      : `Character ${targetInfo.character}`;

  return `<div class="command-output raid-cleanup-output" role="log">
    <div class="command-output-row"><span class="output-label">Mode</span><span class="output-value">${reset ? "Reset Lockouts" : "Preview Only"}</span></div>
    <div class="command-output-row"><span class="output-label">Raid</span><span class="output-value">${escapeHtml(targetInfo.target.label)}</span></div>
    <div class="command-output-row"><span class="output-label">Scope</span><span class="output-value">${escapeHtml(scopeLabel)}</span></div>
    <div class="command-output-row"><span class="output-label">${reset ? "Removed Rows" : "Current Rows"}</span><span class="output-value">${rows.length}</span></div>
    <div class="command-output-row"><span class="output-label">${reset ? "Removed Respawns" : "Current Respawns"}</span><span class="output-value">${reset ? Number(deletedRespawnRows || 0) : respawnRows.reduce((total, row) => total + Number(row.rowCount || 0), 0)}</span></div>
    ${rows.length ? [...byRaid.entries()].map(([raid, raidRows]) => `<div class="command-output-line"><strong>${escapeHtml(raid)}</strong> - ${raidRows.length} bind${raidRows.length === 1 ? "" : "s"}</div>
      ${raidRows.map(row => {
        const resetText = Number(row.effectiveReset || 0) > 0 ? new Date(Number(row.effectiveReset) * 1000).toLocaleString("en-US", { timeZone: "America/New_York" }) : "No reset time stored";
        const typeText = row.rowType === "account" ? "account timer" : "character bind";
        return `<div class="command-output-row"><span class="output-label">${escapeHtml(row.characterName)}</span><span class="output-value">${escapeHtml(row.accountName)} - ${escapeHtml(typeText)} - instance ${Number(row.instance)} - encounters ${Number(row.completedEncounters || 0)} - ${escapeHtml(resetText)}</span></div>`;
      }).join("")}`).join("") : `<div class="command-output-line">No matching raid lockouts found.</div>`}
    ${respawnRows.length ? `<div class="command-output-line"><strong>Saved respawns</strong> - dead creatures/objects that will keep a raid looking cleared until removed.</div>
      ${respawnRows.map(row => {
        const label = raidMapNames[Number(row.map)] || `Map ${Number(row.map)}`;
        const typeText = row.rowType === "gameobject" ? "game objects" : "creatures";
        return `<div class="command-output-row"><span class="output-label">${escapeHtml(label)}</span><span class="output-value">instance ${Number(row.instance)} - ${Number(row.rowCount || 0)} ${escapeHtml(typeText)}</span></div>`;
      }).join("")}` : ""}
  </div>`;
}

async function runRaidLockoutReset(body) {
  const targetInfo = raidLockoutTarget(body);

  try {
    await soapCommand("saveall");
  } catch (error) {
    console.warn("Raid reset saveall failed before lockout check:", error.message);
  }

  const rows = await getRaidLockoutRows(targetInfo);
  const previewInstanceIds = [...new Set(rows.map(row => Number(row.instance)).filter(Number.isFinite))];
  const respawnRows = await getRaidRespawnRows(targetInfo, previewInstanceIds);

  if (targetInfo.mode === "preview") {
    return renderRaidLockoutOutput({ targetInfo, rows, respawnRows, reset: false });
  }

  const onlineRows = await getRaidOnlineRows(targetInfo);
  if (onlineRows.length) {
    const names = onlineRows.slice(0, 12).map(row => `${row.characterName} (${row.accountName})`).join(", ");
    const extra = onlineRows.length > 12 ? `, and ${onlineRows.length - 12} more` : "";
    throw new Error(`Refusing to reset while ${onlineRows.length} online character${onlineRows.length === 1 ? "" : "s"} are still inside ${targetInfo.target.label}: ${names}${extra}. Zone them out first, then run the reset again.`);
  }

  const instanceIds = [...new Set(rows.map(row => Number(row.instance)).filter(Number.isFinite))];
  const scopedAccountIds = await getRaidScopeAccountIds(targetInfo);
  const accountIds = [...new Set([
    ...rows.map(row => Number(row.accountId)).filter(Number.isFinite),
    ...scopedAccountIds
  ])];
  const { mapSql, scopeSql, params } = raidLockoutWhereClause(targetInfo);
  const connection = await db.getConnection();
  let deletedRespawnRows = 0;
  try {
    await connection.query("USE acore_characters");
    await connection.beginTransaction();
    await connection.query(`DELETE ci
      FROM acore_characters.character_instance ci
      JOIN acore_characters.instance i ON i.id = ci.instance
      JOIN acore_characters.characters c ON c.guid = ci.guid
      JOIN acore_auth.account a ON a.id = c.account
      WHERE i.map IN (${mapSql})
        ${scopeSql}`, params);
    if (instanceIds.length) {
      await connection.query(
        `DELETE FROM acore_characters.account_instance_times WHERE instanceId IN (${instanceIds.map(() => "?").join(",")})`,
        instanceIds
      );
    }
    if (accountIds.length) {
      const accountParams = { ...params };
      const accountBinding = bindNumberList("accountId", accountIds, accountParams);
      await connection.query(
        `DELETE ait
        FROM acore_characters.account_instance_times ait
        LEFT JOIN acore_characters.instance i ON i.id = ait.instanceId
        WHERE ait.accountId IN (${accountBinding.sql})
          AND (i.map IN (${mapSql}) OR i.id IS NULL)`,
        accountParams
      );
    }
    if (targetInfo.scope === "all") {
      await connection.query(`DELETE ait
        FROM acore_characters.account_instance_times ait
        LEFT JOIN acore_characters.instance i ON i.id = ait.instanceId
        WHERE i.id IS NULL`);
    } else if (accountIds.length) {
      const accountParams = {};
      const accountBinding = bindNumberList("orphanAccountId", accountIds, accountParams);
      await connection.query(
        `DELETE ait
        FROM acore_characters.account_instance_times ait
        LEFT JOIN acore_characters.instance i ON i.id = ait.instanceId
        WHERE ait.accountId IN (${accountBinding.sql})
          AND i.id IS NULL`,
        accountParams
      );
    }
    if (targetInfo.scope === "all" || instanceIds.length) {
      const respawnParams = { ...params };
      const respawnInstanceSql = targetInfo.scope === "all" ? "" : `AND instanceId IN (${bindNumberList("resetRespawnInstance", instanceIds, respawnParams).sql})`;
      const [creatureResult] = await connection.query(`DELETE FROM acore_characters.creature_respawn
        WHERE mapId IN (${mapSql})
          ${respawnInstanceSql}`, respawnParams);
      const [gameobjectResult] = await connection.query(`DELETE FROM acore_characters.gameobject_respawn
        WHERE mapId IN (${mapSql})
          ${respawnInstanceSql}`, respawnParams);
      deletedRespawnRows = Number(creatureResult.affectedRows || 0) + Number(gameobjectResult.affectedRows || 0);
    }
    await connection.query(`DELETE i
      FROM acore_characters.instance i
      LEFT JOIN acore_characters.character_instance ci ON ci.instance = i.id
      WHERE i.map IN (${mapSql})
        AND ci.instance IS NULL`, params);
    await connection.commit();
  } catch (error) {
    try {
      await connection.rollback();
    } catch (rollbackError) {
      console.error("Raid lockout reset rollback failed:", rollbackError);
    }
    throw error;
  } finally {
    connection.release();
  }

  return renderRaidLockoutOutput({ targetInfo, rows, respawnRows, reset: true, deletedRespawnRows });
}

async function runAdminAction(actionKey, body, source = "admin") {
  let result = "";
  let status = "Action not run";
  let customOutput = "";
  let label = adminActionMap.get(actionKey)?.label || actionKey;

  try {
    if (!adminActionMap.has(actionKey) && !soapActions[actionKey]) throw new Error("Unknown or unsupported server action.");
    if (actionKey === "ahStatus") {
      customOutput = renderAhStatusOutput(await getAhStatusData());
      status = "AHBot Status complete";
      label = "AHBot Status";
    } else if (actionKey === "ahRestockRange") {
      const minLevel = numberParam(body, "minLevel", "Min level", 1, 80);
      const maxLevel = numberParam(body, "maxLevel", "Max level", minLevel, 80);
      customOutput = renderAhRangeOutput(await getAhRangeData(minLevel, maxLevel));
      status = "Auction Range checked";
      label = "Check Level Range";
    } else if (actionKey === "raidBagCleanup") {
      customOutput = await runRaidBagCleanup(body);
      status = String(body.mode || "dry") === "sell" ? "Raid Bag Cleanup sold items" : "Raid Bag Cleanup dry run complete";
      label = "Raid Bag Cleanup";
    } else if (actionKey === "raidLockoutReset") {
      customOutput = await runRaidLockoutReset(body);
      status = String(body.mode || "preview") === "reset" ? "Raid lockouts reset" : "Raid lockout preview complete";
      label = "Raid Lockouts";
    } else {
      const action = buildAdminCommand(actionKey, body);
      label = action.label;
      result = cleanSoapText(await soapCommand(action.command));
      if (actionKey === "pinfo") {
        const characterName = String(body.character || "").trim() || pinfoCharacterName(result);
        const specName = await getCharacterSpecByName(characterName);
        customOutput = renderPinfoOutput(result, specName);
      }
      status = `${action.label} complete`;
    }
  } catch (error) {
    result = error.stack || error.message;
    status = "Action failed";
  }

  await logAdminAction({
    source,
    actionKey,
    label,
    params: adminActionParamsForLog(actionKey, body),
    status,
    success: status !== "Action failed",
    output: customOutput ? "Custom portal output" : result
  });

  return { result, status, customOutput, label };
}

async function getPortalData() {
  const [
    onlineChars,
    totalChars,
    ahCount,
    mountAuctions,
    hordeOnline,
    allianceOnline,
    topPvp,
    onlineByLevel,
    ahByQuality,
    sampleMounts
  ] = await Promise.all([
    scalar("SELECT COUNT(*) value FROM acore_characters.characters WHERE online = 1"),
    scalar("SELECT COUNT(*) value FROM acore_characters.characters"),
    scalar("SELECT COUNT(*) value FROM acore_characters.auctionhouse"),
    scalar(`SELECT COUNT(*) value
      FROM acore_characters.auctionhouse ah
      JOIN acore_characters.item_instance ii ON ii.guid = ah.itemguid
      JOIN acore_world.item_template it ON it.entry = ii.itemEntry
      WHERE it.class = 15 AND it.subclass = 5`),
    scalar(`SELECT COUNT(*) value
      FROM acore_characters.characters
      WHERE online = 1 AND race IN (2,5,6,8,10)`),
    scalar(`SELECT COUNT(*) value
      FROM acore_characters.characters
      WHERE online = 1 AND race IN (1,3,4,7,11)`),
    query(`SELECT guid, name, level, race, class, activeTalentGroup, totalHonorPoints, totalKills
      FROM acore_characters.characters
      ORDER BY totalHonorPoints DESC, totalKills DESC
      LIMIT 8`),
    query(`SELECT
        CASE
          WHEN level BETWEEN 1 AND 19 THEN '1-19'
          WHEN level BETWEEN 20 AND 39 THEN '20-39'
          WHEN level BETWEEN 40 AND 49 THEN '40-49'
          WHEN level BETWEEN 50 AND 59 THEN '50-59'
          WHEN level BETWEEN 60 AND 66 THEN '60-66'
          ELSE '67+'
        END bracket,
        COUNT(*) count
      FROM acore_characters.characters
      WHERE online = 1
      GROUP BY bracket
      ORDER BY MIN(level)`),
    query(`SELECT it.Quality quality, COUNT(*) count
      FROM acore_characters.auctionhouse ah
      JOIN acore_characters.item_instance ii ON ii.guid = ah.itemguid
      JOIN acore_world.item_template it ON it.entry = ii.itemEntry
      GROUP BY it.Quality
      ORDER BY it.Quality`),
    query(`SELECT entry, name, RequiredLevel requiredLevel, RequiredSkillRank riding, Quality quality, SellPrice sellPrice
      FROM acore_world.item_template
      WHERE class = 15 AND subclass = 5
        AND RequiredLevel BETWEEN 20 AND 60
        AND name NOT LIKE 'NPC Equip%'
      ORDER BY RequiredLevel, RequiredSkillRank, quality DESC, name
      LIMIT 16`)
  ]);

  let serverInfo = "Unavailable";
  try {
    const raw = await soapCommand("server info");
    serverInfo = cleanSoapText(raw);
  } catch {
    serverInfo = "SOAP unavailable";
  }

  const topPvpSpecs = await getCharacterSpecs(topPvp);
  const topPvpWithSpecs = topPvp.map(row => ({
    ...row,
    specName: topPvpSpecs.get(Number(row.guid)) || "No Spec"
  }));

  return {
    generatedAt: new Date().toISOString(),
    serverInfo,
    system: {
      load: os.loadavg(),
      memoryTotal: os.totalmem(),
      memoryFree: os.freemem(),
      uptime: os.uptime(),
      cpuCount: os.cpus().length
    },
    counts: {
      onlineChars,
      totalChars,
      ahCount,
      mountAuctions,
      hordeOnline,
      allianceOnline
    },
    topPvp: topPvpWithSpecs,
    onlineByLevel,
    ahByQuality,
    sampleMounts
  };
}

function layout({ title, body, admin = false, user = null }) {
  const showAdminNav = Boolean(user?.isAdmin);
  const username = user?.username ? String(user.username) : "";
  const userInitial = username ? escapeHtml(username.slice(0, 1).toUpperCase()) : "";
  const statusHref = showAdminNav ? "/admin/health" : "/";
  const navIcon = (src, label) => `<img class="nav-icon" src="${src}" alt="" aria-hidden="true"><span>${label}</span>`;
  const primaryLinks = [
    { href: "/", label: "Realm", icon: "/portal-art/portal-logo.png", description: "Realm dashboard" },
    { href: "/talents", label: "Talents", icon: "/portal-art/portal-logo.png", description: "Wrath talent calculators" },
    ...(user
      ? [
        { href: "/account", label: "My Characters", icon: "/portal-art/portal-logo.png", description: "Account characters" },
        { href: "/account/client", label: "Client", icon: "/portal-art/download-icon.png", description: "Download access" }
      ]
      : (registrationEnabled ? [{ href: "/register", label: "Create Account", description: "Request realm access" }] : []))
  ];
  const adminLinks = [
    { href: "/admin", label: "Admin Home", description: "Dashboard and workflows" },
    { href: "/admin/realm", label: "Realm & Population", description: "Live world pulse" },
    { href: "/admin/items", label: "Items", description: "Search and grant" },
    { href: "/admin/character", label: "Characters", description: "Lookup and gear" },
    { href: "/admin/advisor", label: "Advisor", description: "Guided actions" },
    { href: "/admin/commands", label: "All Commands", description: "Full catalog" }
  ];
  const raidLinks = [
    { href: "/admin/raid-roster", label: "Raid Roster", description: "40-man table" },
    { href: "/admin/loot", label: "Raid Loot", description: "Tracked drops" },
    { href: "/admin/commands#raids", label: "Raid Resets", description: "Lockout tools" },
    { href: "/admin/commands#playerbots", label: "Bot Cleanup", description: "Bags and maintenance" }
  ];
  const serverLinks = [
    { href: "/admin/health", label: "Health", description: "Lag and bottlenecks" },
    { href: "/admin/commands#server", label: "Server Tools", description: "Info and save all" },
    { href: "/admin/commands#auction-house", label: "Auction House", description: "AHBot checks" },
    { href: "/admin/commands#accounts", label: "Accounts", description: "Account admin" }
  ];
  const navMenu = (src, label, links) => `<div class="nav-menu">
    <button class="nav-menu-label" type="button" aria-haspopup="true" aria-expanded="false">${navIcon(src, label)}</button>
    <div class="nav-menu-panel" role="menu" aria-label="${escapeHtml(label)} navigation">
      ${links.map(link => `<a href="${escapeHtml(link.href)}" role="menuitem"><strong>${escapeHtml(link.label)}</strong>${link.description ? `<small>${escapeHtml(link.description)}</small>` : ""}</a>`).join("")}
    </div>
  </div>`;
  const mobileLink = (link) => `<a href="${escapeHtml(link.href)}">${link.icon ? `<img class="nav-icon" src="${escapeHtml(link.icon)}" alt="" aria-hidden="true">` : ""}<span><strong>${escapeHtml(link.label)}</strong>${link.description ? `<small>${escapeHtml(link.description)}</small>` : ""}</span></a>`;
  const mobileGroup = (label, links) => `<section class="mobile-nav-group"><h2>${escapeHtml(label)}</h2>${links.map(mobileLink).join("")}</section>`;
  const adminSidebar = showAdminNav && admin ? `<aside class="admin-sidebar" aria-label="Admin navigation">
    <div class="admin-sidebar-section">
      <span>Core</span>
      ${[
        { href: "/admin", label: "Dashboard", description: "Overview" },
        { href: "/admin/realm", label: "Realm", description: "Population pulse" },
        { href: "/admin/health", label: "Health", description: "Lag triage" }
      ].map(mobileLink).join("")}
    </div>
    <div class="admin-sidebar-section">
      <span>Players</span>
      ${[
        { href: "/admin/character", label: "Characters", description: "Lookup and gear" },
        { href: "/admin/raid-roster", label: "Raid Roster", description: "Team table" },
        { href: "/admin/advisor", label: "Advisor", description: "Guided checks" }
      ].map(mobileLink).join("")}
    </div>
    <div class="admin-sidebar-section">
      <span>Inventory</span>
      ${[
        { href: "/admin/items", label: "Items", description: "Search and grant" },
        { href: "/admin/loot", label: "Raid Loot", description: "Tracked drops" },
        { href: "/admin/commands#auction-house", label: "Auction House", description: "AHBot tools" }
      ].map(mobileLink).join("")}
    </div>
    <div class="admin-sidebar-section">
      <span>Server</span>
      ${[
        { href: "/admin/commands", label: "Commands", description: "Full catalog" },
        { href: "/admin/commands#server", label: "Server Tools", description: "SOAP helpers" },
        { href: "/admin/commands#accounts", label: "Accounts", description: "User admin" }
      ].map(mobileLink).join("")}
    </div>
  </aside>` : "";
  const mainBody = adminSidebar ? `${adminSidebar}<div class="admin-content">${body}</div>` : body;
  const accountControls = user
    ? `<div class="nav-session" aria-label="Signed in account">
        <a class="account-pill" href="/account" title="Signed in as ${escapeHtml(username)}">
          <span class="account-avatar" aria-hidden="true">${userInitial}</span>
          <span class="account-copy"><span>Signed in</span><strong>${escapeHtml(username)}</strong></span>
        </a>
        <form class="nav-form" action="/logout" method="post"><button class="logout-button" type="submit">${navIcon("/portal-art/portal-logo.png", "Logout")}</button></form>
      </div>`
    : '<a class="login-button" href="/login">Login</a>';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <link rel="stylesheet" href="/styles.css">
  <script>
    const whTooltips = {
      colorLinks: false,
      iconizeLinks: false,
      renameLinks: false
    };
  </script>
  <script src="https://wow.zamimg.com/js/tooltips.js" async></script>
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">
      <img class="brand-mark" src="/portal-art/portal-logo.png" alt="" aria-hidden="true">
      <span><strong>AzerothCore</strong><small>AzerothCore Realm</small></span>
    </a>
    <a class="top-realm-status checking" href="${statusHref}" aria-live="polite" data-realm-status>
      <img src="/portal-art/realm-online.png" alt="" aria-hidden="true" data-realm-status-img>
    </a>
    <button class="mobile-menu-toggle" type="button" aria-expanded="false" aria-controls="mobile-nav-drawer" data-mobile-menu-toggle>
      <span class="mobile-menu-lines" aria-hidden="true"><i></i><i></i><i></i></span>
      <span>Menu</span>
    </button>
    <nav>
      ${primaryLinks.map(link => link.icon ? `<a href="${escapeHtml(link.href)}">${navIcon(link.icon, link.label)}</a>` : `<a href="${escapeHtml(link.href)}">${escapeHtml(link.label)}</a>`).join("")}
      ${showAdminNav ? navMenu("/portal-art/portal-logo.png", "Admin", adminLinks) : ""}
      ${showAdminNav ? navMenu("/portal-art/portal-logo.png", "Raids", raidLinks) : ""}
      ${showAdminNav ? navMenu("/portal-art/portal-logo.png", "Server", serverLinks) : ""}
      ${accountControls}
    </nav>
  </header>
  <div class="mobile-nav-backdrop" data-mobile-nav-close></div>
  <aside class="mobile-nav-drawer" id="mobile-nav-drawer" aria-hidden="true">
    <div class="mobile-nav-head">
      <div><strong>AzerothCore</strong><small>${user ? `Signed in as ${escapeHtml(username)}` : "AzerothCore Portal"}</small></div>
      <button type="button" data-mobile-nav-close aria-label="Close menu">Close</button>
    </div>
    ${mobileGroup("Portal", primaryLinks)}
    ${showAdminNav ? mobileGroup("Admin", adminLinks) : ""}
    ${showAdminNav ? mobileGroup("Raids", raidLinks) : ""}
    ${showAdminNav ? mobileGroup("Server", serverLinks) : ""}
    ${user ? `<form class="mobile-nav-logout" action="/logout" method="post"><button type="submit">Logout ${escapeHtml(username)}</button></form>` : ""}
  </aside>
  <main class="${admin ? "admin-shell" : ""}">${mainBody}</main>
  <script>
    (() => {
      const menus = Array.from(document.querySelectorAll(".nav-menu"));
      if (!menus.length) return;
      const closeMenus = () => {
        menus.forEach(menu => {
          menu.classList.remove("open");
          const button = menu.querySelector(".nav-menu-label");
          if (button) button.setAttribute("aria-expanded", "false");
        });
      };
      const updatePanelTop = () => {
        const topbar = document.querySelector(".topbar");
        if (!topbar) return;
        document.documentElement.style.setProperty("--nav-panel-top", Math.ceil(topbar.getBoundingClientRect().bottom + 8) + "px");
      };
      menus.forEach(menu => {
        const button = menu.querySelector(".nav-menu-label");
        if (!button) return;
        button.addEventListener("click", event => {
          event.preventDefault();
          event.stopPropagation();
          const willOpen = !menu.classList.contains("open");
          closeMenus();
          if (willOpen) {
            updatePanelTop();
            menu.classList.add("open");
            button.setAttribute("aria-expanded", "true");
          }
        });
      });
      document.addEventListener("click", event => {
        if (!event.target.closest(".nav-menu")) closeMenus();
      });
      document.addEventListener("keydown", event => {
        if (event.key === "Escape") closeMenus();
      });
      window.addEventListener("resize", updatePanelTop);
      window.addEventListener("scroll", updatePanelTop, { passive: true });
    })();

    (() => {
      const toggle = document.querySelector("[data-mobile-menu-toggle]");
      const drawer = document.querySelector(".mobile-nav-drawer");
      const closers = Array.from(document.querySelectorAll("[data-mobile-nav-close]"));
      if (!toggle || !drawer) return;
      const setOpen = (open) => {
        document.body.classList.toggle("mobile-nav-open", open);
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
        drawer.setAttribute("aria-hidden", open ? "false" : "true");
      };
      toggle.addEventListener("click", event => {
        event.preventDefault();
        setOpen(!document.body.classList.contains("mobile-nav-open"));
      });
      closers.forEach(closer => closer.addEventListener("click", () => setOpen(false)));
      drawer.querySelectorAll("a").forEach(link => link.addEventListener("click", () => setOpen(false)));
      document.addEventListener("keydown", event => {
        if (event.key === "Escape") setOpen(false);
      });
    })();

    (() => {
      const status = document.querySelector("[data-realm-status]");
      if (!status) return;
      const image = status.querySelector("[data-realm-status-img]");
      const setState = (online) => {
        status.classList.toggle("online", online);
        status.classList.toggle("offline", !online);
        status.classList.remove("checking");
        if (image) image.src = online ? "/portal-art/realm-online.png" : "/portal-art/realm-offline.png";
      };
      fetch("/api/status", { headers: { Accept: "application/json" } })
        .then(response => response.ok ? response.json() : null)
        .then(data => setState(Boolean(data && data.serverInfo && data.serverInfo !== "SOAP unavailable")))
        .catch(() => setState(false));
    })();
  </script>
</body>
</html>`;
}

function statCard(label, value, note = "") {
  return `<section class="stat-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(note)}</small></section>`;
}

function renderField(field) {
  const type = field.type || "text";
  if (type === "select") {
    const options = (field.options || []).map(option => {
      const value = typeof option === "object" ? option.value : option;
      const label = typeof option === "object" ? option.label : option;
      return `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`;
    }).join("");
    return `<label><span>${escapeHtml(field.label)}</span><select name="${escapeHtml(field.name)}" ${field.required ? "required" : ""}>${options}</select></label>`;
  }

  return `<label><span>${escapeHtml(field.label)}</span><input name="${escapeHtml(field.name)}" type="${escapeHtml(type)}" placeholder="${escapeHtml(field.placeholder || "")}" ${field.min ? `min="${escapeHtml(field.min)}"` : ""} ${field.max ? `max="${escapeHtml(field.max)}"` : ""} ${field.required ? "required" : ""}></label>`;
}

function renderAdminTool(tool) {
  return `<form class="tool-card" action="/admin/soap" method="post">
    <input type="hidden" name="action" value="${escapeHtml(tool.action)}">
    <div class="tool-copy">
      <strong>${escapeHtml(tool.label)}</strong>
      <span>${escapeHtml(tool.description)}</span>
    </div>
    ${tool.fields.length ? `<div class="tool-fields">${tool.fields.map(renderField).join("")}</div>` : ""}
    <button class="secondary tool-run" type="submit">Run</button>
  </form>`;
}

function renderAdminHub() {
  const commandCount = adminToolGroups.reduce((sum, group) => sum + group.tools.length, 0);
  const cards = [
    { href: "/admin/realm", title: "Realm & Population", body: "See where the world is active, faction balance, class spread, and online zones.", meta: "Live world pulse" },
    { href: "/admin/items", title: "Items", body: "Search Wowhead-linked item templates and grant them without copy-paste.", meta: "Search + grant workflow" },
    { href: "/admin/health", title: "Health", body: "Check lag signals, bot population, auction depth, and realm bottlenecks.", meta: "Server triage" },
    { href: "/admin/character", title: "Characters", body: "Look up character records, gear, specs, positions, and account ownership.", meta: "Character records" },
    { href: "/admin/raid-roster", title: "Raid Roster", body: "Sort your 40-character raid team by class, spec, level, and gear.", meta: "Raid readiness" },
    { href: "/admin/loot", title: "Raid Loot", body: "Review rare, epic, and legendary drops from raid runs.", meta: "Loot tracker" },
    { href: "/admin/advisor", title: "Advisor", body: "Ask for guided checks and approved admin actions in plain language.", meta: "Local AI assistant" },
    { href: "/admin/commands", title: "All Commands", body: "Open the full command catalog when you need a less common action.", meta: `${commandCount} actions` }
  ];

  return `<section class="admin-command-center admin-hub">
    <div class="panel-head admin-command-head">
      <h2>Admin Console</h2>
      <span>Fast paths for the jobs you actually do</span>
    </div>
    <form class="admin-global-search" action="/admin/items" method="get">
      <label>
        <span>Search item templates</span>
        <input name="q" placeholder="Arcanite Reaper, devilsaur, essence, 18705...">
      </label>
      <button type="submit">Search Items</button>
    </form>
    <form class="admin-quick-action av-queue-action" action="/admin/soap" method="post">
      <input type="hidden" name="action" value="queueAvRaid">
      <div>
        <span class="result-kicker">Alterac Valley</span>
        <strong>Queue 40-Man Raid</strong>
        <small>Queues the raid from the server side, bypassing the battlemaster UI limit.</small>
      </div>
      <label>
        <span>Raid leader</span>
        <input name="character" value="Charactername" placeholder="Charactername" required>
      </label>
      <button type="submit">Queue AV</button>
    </form>
    <div class="admin-hub-grid">
      ${cards.map(card => `<a class="admin-hub-card" href="${escapeHtml(card.href)}">
        <span>${escapeHtml(card.meta)}</span>
        <strong>${escapeHtml(card.title)}</strong>
        <small>${escapeHtml(card.body)}</small>
      </a>`).join("")}
    </div>
  </section>`;
}

function renderAllAdminTools() {
  return `<section class="admin-command-center">
    <div class="panel-head admin-command-head">
      <h2>All Admin Commands</h2>
      <span>Full catalog, grouped by the job you are trying to do</span>
    </div>
    <div class="admin-section-nav" aria-label="Admin tool sections">
      <a href="/admin">
        <strong>Admin Home</strong>
        <span>Workflow dashboard</span>
      </a>
      <a href="/admin/items">
        <strong>Items</strong>
        <span>Search and grant</span>
      </a>
      <a href="/admin/raid-roster">
        <strong>Raid Roster</strong>
        <span>40-man readiness table</span>
      </a>
      <a href="/admin/realm">
        <strong>Realm & Population</strong>
        <span>World pulse</span>
      </a>
      ${adminToolGroups.map(group => `<a href="#${escapeHtml(group.id)}">
        <strong>${escapeHtml(group.title)}</strong>
        <span>${group.tools.length} action${group.tools.length === 1 ? "" : "s"}</span>
      </a>`).join("")}
    </div>
  </section>
  <section class="admin-tools">
    ${adminToolGroups.map(group => `<article id="${escapeHtml(group.id)}" class="tool-group">
      <div class="panel-head">
        <h2>${escapeHtml(group.title)}</h2>
        <span>${escapeHtml(group.subtitle)}</span>
      </div>
      <div class="tool-list">
        ${group.tools.map(renderAdminTool).join("")}
      </div>
    </article>`).join("")}
  </section>`;
}

function renderAdminItemsPage({ search = "", results = [], characters = [], resultBody = "" } = {}) {
  const favoriteCharacters = ["Charactername", "Tankname", "Healername", "Warlockname", "Magename", "Shamanname", "Altname"];
  const characterOptions = [...new Set([...favoriteCharacters, ...characters.map(row => row.name)])]
    .map(name => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`)
    .join("");

  return `<section class="page-head character-lookup-head">
    <div>
      <p class="eyebrow">Admin Workflow</p>
      <h1>Items</h1>
      <p class="hero-copy">Search item templates, inspect the WotLK Wowhead link, and send the item without copying IDs between command boxes.</p>
    </div>
    <a class="button ghost back-button" href="/admin"><span>Back</span></a>
  </section>

  ${resultBody}

  <section class="item-workflow-shell">
    <article class="panel item-search-panel">
      <div class="panel-head">
        <h2>Search and Grant</h2>
        <span>${results.length ? `${results.length} result${results.length === 1 ? "" : "s"}` : "World item templates"}</span>
      </div>
      <form class="item-search-form" action="/admin/items" method="get">
        <label>
          <span>Item name or ID</span>
          <input name="q" value="${escapeHtml(search)}" placeholder="Arcanite Reaper, devilsaur, 18705..." autofocus>
        </label>
        <button type="submit">Search</button>
      </form>
      <p class="muted">Use mail for offline-safe grants. Direct bag is useful only when the character is online and you want the item immediately.</p>
    </article>

    <article class="panel item-grant-panel">
      <div class="panel-head"><h2>Quick Grant</h2><span>Manual item ID</span></div>
      <form class="item-grant-form" action="/admin/soap" method="post">
        <input type="hidden" name="action" value="addItem">
        <input type="hidden" name="returnTo" value="items">
        <input type="hidden" name="search" value="${escapeHtml(search)}">
        <label><span>Character</span><input name="character" list="admin-character-list" placeholder="Start typing a character..." required></label>
        <label><span>Item ID</span><input name="entry" type="number" min="1" placeholder="18705" required></label>
        <label><span>Count</span><input name="count" type="number" min="1" max="200" value="1"></label>
        <label><span>Delivery</span><select name="delivery"><option value="mail">Mail - offline safe</option><option value="direct">Direct Bag - online only</option></select></label>
        <button type="submit">Grant Item</button>
      </form>
    </article>
  </section>

  <datalist id="admin-character-list">${characterOptions}</datalist>

  <section class="item-results">
    ${results.length ? results.map(item => renderItemWorkflowCard(item, characterOptions)).join("") : `<article class="panel empty-state">
      <h2>${search ? "No matching items found." : "Search for an item to begin."}</h2>
      <p class="muted">${search ? "Try a broader item name, or paste the numeric item ID directly into Quick Grant." : "The next step will appear right here: result cards with prefilled grant buttons and WotLK Wowhead hover links."}</p>
    </article>`}
  </section>`;
}

function renderItemWorkflowCard(item, characterOptions) {
  const entry = Number(item.entry);
  const quality = Number(item.Quality ?? item.quality ?? 0);
  const itemLevel = Number(item.ItemLevel ?? item.itemLevel ?? 0);
  const requiredLevel = Number(item.RequiredLevel ?? item.requiredLevel ?? 0);
  const itemClass = Number(item.class ?? item.itemClass ?? 0);
  const inventoryType = Number(item.InventoryType ?? item.inventoryType ?? 0);
  const sellPrice = Number(item.SellPrice ?? item.sellPrice ?? 0);
  const name = item.name || `Item ${entry}`;

  return `<article class="item-result-card q${quality}">
    <div class="item-result-main">
      <div class="item-quality-rune"></div>
      <div>
        ${renderWowheadItemLink({ entry, name, quality, className: "item-result-name", content: `<strong>${escapeHtml(name)}</strong>` })}
        <div class="item-meta">
          <span>ID ${entry}</span>
          <span>${escapeHtml(qualityName(quality))}</span>
          ${itemLevel ? `<span>iLvl ${itemLevel}</span>` : ""}
          ${requiredLevel ? `<span>Req ${requiredLevel}</span>` : ""}
          <span>${escapeHtml(itemClassNames[itemClass] || `Class ${itemClass}`)}</span>
          ${inventoryType ? `<span>Slot ${inventoryType}</span>` : ""}
          ${sellPrice ? `<span>${escapeHtml(formatGold(sellPrice))} vendor</span>` : ""}
        </div>
      </div>
    </div>
    <form class="item-inline-grant" action="/admin/soap" method="post">
      <input type="hidden" name="action" value="addItem">
      <input type="hidden" name="returnTo" value="items">
      <input type="hidden" name="search" value="${escapeHtml(item.search || "")}">
      <input type="hidden" name="entry" value="${entry}">
      <label><span>Character</span><input name="character" list="admin-character-list" placeholder="Start typing..." required></label>
      <label><span>Count</span><input name="count" type="number" min="1" max="200" value="1"></label>
      <label><span>Delivery</span><select name="delivery"><option value="mail">Mail</option><option value="direct">Direct</option></select></label>
      <button type="submit">Send</button>
    </form>
  </article>`;
}

async function searchAdminItems(search) {
  const term = String(search || "").trim();
  if (!term) return [];

  const numericId = /^\d+$/.test(term) ? Number(term) : 0;
  const rows = await query(`SELECT entry, name, Quality, ItemLevel, RequiredLevel, InventoryType, class, subclass, SellPrice
    FROM acore_world.item_template
    WHERE (:entry > 0 AND entry = :entry)
      OR (:entry = 0 AND LOWER(name) LIKE :search)
    ORDER BY
      CASE WHEN entry = :entry THEN 0 ELSE 1 END,
      Quality DESC,
      ItemLevel DESC,
      name
    LIMIT 60`, {
      entry: numericId,
      search: `%${term.toLowerCase()}%`
    });

  return rows.map(row => ({ ...row, search: term }));
}

async function getAdminCharacterChoices() {
  return await query(`SELECT c.name
    FROM acore_characters.characters c
    JOIN acore_auth.account a ON a.id = c.account
    LEFT JOIN acore_auth.portal_users pu ON pu.account_id = a.id
    WHERE pu.account_id IS NOT NULL OR a.gmlevel > 0
    ORDER BY c.name
    LIMIT 500`);
}

function renderAdminActionResultPanel({ actionKey, status, resultState, resultBadge, resultHead, customOutput, result, kicker = "Admin Action" }) {
  return `<article class="panel result-panel ${resultState}">
    <div class="result-hero">
      <div>
        <span class="result-kicker">${escapeHtml(kicker)}</span>
        <h2>${escapeHtml(status)}</h2>
      </div>
      <span class="result-pill">${escapeHtml(resultBadge)}</span>
    </div>
    <div class="command-result">
      <div class="command-result-head">
        <span>${escapeHtml(resultHead.title)}</span>
        <small>${escapeHtml(resultHead.subtitle)}</small>
      </div>
      ${customOutput || renderCommandOutput(result, actionKey)}
    </div>
  </article>`;
}

function parseMilliseconds(text) {
  const match = String(text || "").match(/(\d+(?:\.\d+)?)\s*ms/i);
  if (match) return Number(match[1]);
  const seconds = String(text || "").match(/(\d+(?:\.\d+)?)\s*s/i);
  return seconds ? Number(seconds[1]) * 1000 : 0;
}

function healthStatusClass(value) {
  return value === "Action Needed" ? "bad" : value === "Watch" ? "watch" : "good";
}

function healthVerdict({ cpuPct, memoryPct, dbLatencyMs, tickMs, realmOnline }) {
  const warnings = [];
  if (!realmOnline) warnings.push("Worldserver SOAP is unavailable.");
  if (tickMs >= 250) warnings.push(`World update diff is high at ${Math.round(tickMs)} ms.`);
  if (cpuPct >= 85) warnings.push(`CPU pressure is high at ${cpuPct}%.`);
  if (memoryPct >= 88) warnings.push(`Memory use is high at ${memoryPct}%.`);
  if (dbLatencyMs >= 150) warnings.push(`Database response is slow at ${dbLatencyMs} ms.`);

  if (!realmOnline || tickMs >= 500 || cpuPct >= 95 || memoryPct >= 95 || dbLatencyMs >= 300) {
    return { status: "Action Needed", summary: warnings[0] || "A major health signal needs attention.", warnings };
  }

  if (warnings.length) {
    return { status: "Watch", summary: warnings[0], warnings };
  }

  return { status: "Healthy", summary: "Realm tick, CPU, memory, and database response are in a comfortable range.", warnings: [] };
}

async function timedDbPing() {
  const started = Date.now();
  await query("SELECT 1 value");
  return Date.now() - started;
}

async function getAdminHealthData(baseData) {
  const started = Date.now();
  const [
    dbLatencyMs,
    botAccounts,
    topZones,
    onlineByFactionLevel,
    ahByHouse,
    ahByLevel,
    ahGearByQuality
  ] = await Promise.all([
    timedDbPing(),
    query(`SELECT
        CASE
          WHEN a.gmlevel > 0 THEN 'GM accounts'
          ELSE 'World/random'
        END bucket,
        COUNT(*) count
      FROM acore_characters.characters c
      JOIN acore_auth.account a ON a.id = c.account
      WHERE c.online = 1
      GROUP BY bucket
      ORDER BY bucket`),
    query(`SELECT c.map, c.zone, COALESCE(NULLIF(area.AreaName_Lang_enUS, ''), '') zoneName, COUNT(*) count
      FROM acore_characters.characters c
      LEFT JOIN acore_world.areatable_dbc area ON area.ID = c.zone
      WHERE c.online = 1
      GROUP BY c.map, c.zone, zoneName
      ORDER BY count DESC, zoneName
      LIMIT 12`),
    query(`SELECT
        CASE WHEN c.race IN (2,5,6,8,10) THEN 'Horde' ELSE 'Alliance' END faction,
        CASE
          WHEN c.level BETWEEN 1 AND 19 THEN '1-19'
          WHEN c.level BETWEEN 20 AND 39 THEN '20-39'
          WHEN c.level BETWEEN 40 AND 49 THEN '40-49'
          WHEN c.level BETWEEN 50 AND 59 THEN '50-59'
          WHEN c.level BETWEEN 60 AND 66 THEN '60-66'
          ELSE '67+'
        END bracket,
        COUNT(*) count
      FROM acore_characters.characters c
      WHERE c.online = 1
      GROUP BY faction, bracket
      ORDER BY faction, MIN(c.level)`),
    query(`SELECT houseid, COUNT(*) count
      FROM acore_characters.auctionhouse
      GROUP BY houseid
      ORDER BY houseid`),
    query(`SELECT
        CASE
          WHEN it.RequiredLevel BETWEEN 1 AND 19 THEN '1-19'
          WHEN it.RequiredLevel BETWEEN 20 AND 39 THEN '20-39'
          WHEN it.RequiredLevel BETWEEN 40 AND 49 THEN '40-49'
          WHEN it.RequiredLevel BETWEEN 50 AND 59 THEN '50-59'
          WHEN it.RequiredLevel BETWEEN 60 AND 66 THEN '60-66'
          ELSE '67+'
        END bracket,
        COUNT(*) count
      FROM acore_characters.auctionhouse ah
      JOIN acore_characters.item_instance ii ON ii.guid = ah.itemguid
      JOIN acore_world.item_template it ON it.entry = ii.itemEntry
      WHERE it.RequiredLevel BETWEEN 1 AND 66
      GROUP BY bracket
      ORDER BY MIN(it.RequiredLevel)`),
    query(`SELECT it.Quality quality, COUNT(*) count
      FROM acore_characters.auctionhouse ah
      JOIN acore_characters.item_instance ii ON ii.guid = ah.itemguid
      JOIN acore_world.item_template it ON it.entry = ii.itemEntry
      WHERE it.class IN (2,4) AND it.RequiredLevel BETWEEN 50 AND 65
      GROUP BY it.Quality
      ORDER BY it.Quality`)
  ]);

  return {
    generatedMs: Date.now() - started,
    dbLatencyMs,
    botAccounts,
    topZones,
    onlineByFactionLevel,
    ahByHouse,
    ahByLevel,
    ahGearByQuality
  };
}

function healthMetric(label, value, note = "", status = "good") {
  return `<article class="health-metric ${escapeHtml(status)}">
    <span>${escapeHtml(label)}</span>
    <strong>${escapeHtml(value)}</strong>
    <small>${escapeHtml(note)}</small>
  </article>`;
}

function renderHealthBars(rows, total, labelKey = "bracket") {
  return `<div class="health-bars">${rows.map(row => {
    const count = Number(row.count || 0);
    const pct = Math.min(100, Math.round((count / Math.max(1, total)) * 100));
    return `<div class="bar-row"><span>${escapeHtml(row[labelKey] || "Unknown")}</span><div><i style="width:${pct}%"></i></div><strong>${count.toLocaleString()}</strong></div>`;
  }).join("") || `<p class="muted">No rows found.</p>`}</div>`;
}

async function getAdminRealmData() {
  const cityZones = [1519, 1537, 1637, 1638, 1657, 1497, 3487, 3557];
  const dungeonMaps = [33, 34, 36, 43, 47, 48, 70, 90, 109, 129, 189, 209, 229, 230, 269, 289, 329, 349, 389, 429, 540, 542, 543, 545, 546, 547, 552, 553, 554, 555, 556, 557, 558, 560, 574, 575, 576, 578, 585, 595, 599, 600, 601, 602, 604, 608, 619, 632, 650, 658, 668];
  const raidMaps = [249, 309, 409, 469, 509, 531, 532, 533, 534, 544, 548, 550, 564, 565, 580, 603, 615, 616, 624, 631, 649, 724];
  const battlegroundMaps = [30, 489, 529, 559, 562, 566, 572, 607, 617, 628];
  const cityList = cityZones.join(",");
  const dungeonList = dungeonMaps.join(",");
  const raidList = raidMaps.join(",");
  const battlegroundList = battlegroundMaps.join(",");

  const [
    summary,
    factionRows,
    classRows,
    raceRows,
    levelRows,
    topZones,
    locationRows,
    accountRows,
    worldBosses,
    activity
  ] = await Promise.all([
    query(`SELECT
        COUNT(*) totalCharacters,
        SUM(online = 1) onlineNow,
        SUM(level = 80) level80,
        ROUND(AVG(level), 1) avgLevel,
        COALESCE(SUM(money), 0) totalCopper,
        (SELECT COUNT(*) FROM acore_characters.guild) guildCount
      FROM acore_characters.characters`),
    query(`SELECT CASE WHEN race IN (2,5,6,8,10) THEN 'Horde' ELSE 'Alliance' END faction, COUNT(*) count
      FROM acore_characters.characters
      GROUP BY faction
      ORDER BY faction`),
    query(`SELECT class, COUNT(*) count
      FROM acore_characters.characters
      GROUP BY class
      ORDER BY count DESC, class`),
    query(`SELECT race, COUNT(*) count
      FROM acore_characters.characters
      GROUP BY race
      ORDER BY count DESC, race`),
    query(`SELECT
        CASE
          WHEN level BETWEEN 1 AND 10 THEN '1-10'
          WHEN level BETWEEN 11 AND 20 THEN '11-20'
          WHEN level BETWEEN 21 AND 30 THEN '21-30'
          WHEN level BETWEEN 31 AND 40 THEN '31-40'
          WHEN level BETWEEN 41 AND 50 THEN '41-50'
          WHEN level BETWEEN 51 AND 60 THEN '51-60'
          WHEN level BETWEEN 61 AND 70 THEN '61-70'
          ELSE '71-80'
        END bracket,
        COUNT(*) count,
        MIN(level) minLevel
      FROM acore_characters.characters
      GROUP BY bracket
      ORDER BY minLevel`),
    query(`SELECT c.map, c.zone, COALESCE(NULLIF(area.AreaName_Lang_enUS, ''), '') zoneName, COUNT(*) count
      FROM acore_characters.characters c
      LEFT JOIN acore_world.areatable_dbc area ON area.ID = c.zone
      WHERE c.online = 1
      GROUP BY c.map, c.zone, zoneName
      ORDER BY count DESC, zoneName
      LIMIT 10`),
    query(`SELECT
        CASE
          WHEN c.zone IN (${cityList}) THEN 'Cities'
          WHEN c.map IN (${dungeonList}) THEN 'Dungeons'
          WHEN c.map IN (${raidList}) THEN 'Raids'
          WHEN c.map IN (${battlegroundList}) THEN 'Battlegrounds'
          ELSE 'Out in the world'
        END bucket,
        COUNT(*) count
      FROM acore_characters.characters c
      WHERE c.online = 1
      GROUP BY bucket
      ORDER BY FIELD(bucket, 'Out in the world', 'Cities', 'Dungeons', 'Raids', 'Battlegrounds')`),
    query(`SELECT
        CASE
          WHEN a.gmlevel > 0 THEN 'GM accounts'
          ELSE 'World/random'
        END bucket,
        COUNT(*) count
      FROM acore_characters.characters c
      JOIN acore_auth.account a ON a.id = c.account
      WHERE c.online = 1
      GROUP BY bucket
      ORDER BY bucket`),
    getWorldBossStatuses(),
    getAdminActionHistory(8)
  ]);

  return {
    summary: summary[0] || {},
    factionRows,
    classRows,
    raceRows,
    levelRows,
    topZones,
    locationRows,
    accountRows,
    worldBosses,
    activity
  };
}

async function getWorldBossStatuses() {
  const bossSql = trackedWorldBosses
    .map(boss => `SELECT ${Number(boss.entry)} entry, ${sqlString(boss.name)} displayName, ${sqlString(boss.location)} locationName`)
    .join(" UNION ALL ");

  const rows = await query(`SELECT
      boss.entry,
      boss.displayName,
      boss.locationName,
      c.guid,
      c.map,
      c.zoneId,
      COALESCE(cr.respawntime, 0) respawnTime
    FROM (${bossSql}) boss
    LEFT JOIN acore_world.creature c ON c.id = boss.entry
    LEFT JOIN acore_characters.creature_respawn cr ON cr.guid = c.guid AND cr.instanceId = 0
    ORDER BY boss.entry, c.guid`);

  const now = Math.floor(Date.now() / 1000);
  return trackedWorldBosses.map(boss => {
    const matches = rows.filter(row => Number(row.entry) === Number(boss.entry));
    if (!matches.length || !matches.some(row => row.guid)) {
      return { ...boss, status: "not-placed", statusLabel: "Not placed", note: "No world spawn found" };
    }

    const active = matches.find(row => Number(row.respawnTime || 0) <= now);
    if (active) {
      return {
        ...boss,
        guid: Number(active.guid),
        map: Number(active.map || 0),
        status: "available",
        statusLabel: "Available",
        note: boss.location
      };
    }

    const nextRespawn = Math.min(...matches.map(row => Number(row.respawnTime || 0)).filter(Boolean));
    return {
      ...boss,
      guid: Number(matches[0].guid),
      map: Number(matches[0].map || 0),
      status: "respawning",
      statusLabel: "Respawning",
      respawnTime: nextRespawn,
      note: `${formatTimeUntil(nextRespawn)} - ${formatPortalDate(new Date(nextRespawn * 1000))}`
    };
  });
}

function keyedCount(rows, keyField, keyValue) {
  return Number((rows || []).find(row => String(row[keyField]) === String(keyValue))?.count || 0);
}

function renderPopulationBars(rows, total, { label, color } = {}) {
  return `<div class="realm-pop-bars">${rows.map(row => {
    const count = Number(row.count || 0);
    const pct = Math.min(100, Math.round((count / Math.max(1, total)) * 100));
    const rowLabel = typeof label === "function" ? label(row) : row[label || "label"];
    const rowColor = typeof color === "function" ? color(row) : color;
    return `<div class="realm-pop-row" style="${rowColor ? `--bar-color:${escapeHtml(rowColor)}` : ""}">
      <span>${escapeHtml(rowLabel || "Unknown")}</span>
      <div><i style="width:${pct}%"></i></div>
      <strong>${count.toLocaleString()} <small>${pct}%</small></strong>
    </div>`;
  }).join("") || `<p class="muted">No rows found.</p>`}</div>`;
}

function renderWorldBossPanel(rows = []) {
  const counts = rows.reduce((acc, row) => {
    acc[row.status] = Number(acc[row.status] || 0) + 1;
    return acc;
  }, {});
  const summary = `${Number(counts.available || 0)} available / ${Number(counts.respawning || 0)} respawning / ${Number(counts["not-placed"] || 0)} not placed`;

  return `<article class="panel world-boss-panel">
    <div class="panel-head"><h2>World Bosses</h2><span>${escapeHtml(summary)}</span></div>
    <div class="world-boss-list">
      ${rows.map(row => `<div class="world-boss-card ${escapeHtml(row.status)}">
        <img class="world-boss-icon" src="${escapeHtml(row.icon || "")}" alt="" loading="lazy">
        <div class="world-boss-copy">
          <div>
            <strong>${escapeHtml(row.name)}</strong>
            <span>${escapeHtml(row.location || mapLabel(row.map))}</span>
          </div>
          <b>${escapeHtml(row.statusLabel)}</b>
          <small>${escapeHtml(row.note || "")}</small>
        </div>
      </div>`).join("") || `<p class="muted">No tracked world bosses found.</p>`}
    </div>
  </article>`;
}

function renderAdminRealmPage(realmData, portalData) {
  const summary = realmData.summary || {};
  const totalCharacters = Number(summary.totalCharacters || 0);
  const onlineNow = Number(summary.onlineNow || 0);
  const horde = keyedCount(realmData.factionRows, "faction", "Horde");
  const alliance = keyedCount(realmData.factionRows, "faction", "Alliance");
  const totalFaction = Math.max(1, horde + alliance);
  const hordePct = Math.round((horde / totalFaction) * 100);
  const alliancePct = 100 - hordePct;
  const accountTotal = realmData.accountRows.reduce((sum, row) => sum + Number(row.count || 0), 0);
  const location = name => Number(realmData.locationRows.find(row => row.bucket === name)?.count || 0);

  return `<section class="page-head character-lookup-head">
    <div>
      <p class="eyebrow">Live Realm</p>
      <h1>Realm & Population</h1>
      <p class="hero-copy">A living snapshot of AzerothCore: where characters are, how the factions look, and whether the world feels alive.</p>
    </div>
    <a class="button ghost back-button" href="/admin"><span>Back</span></a>
  </section>

  <section class="realm-pulse">
    ${statCard("Characters", totalCharacters.toLocaleString(), "total characters")}
    ${statCard("Online Now", onlineNow.toLocaleString(), "players and bots")}
    ${statCard("Guilds", Number(summary.guildCount || 0).toLocaleString(), "active guild records")}
    ${statCard("Average Level", String(summary.avgLevel || "0"), "all characters")}
    ${statCard("Level 80", Number(summary.level80 || 0).toLocaleString(), "max level characters")}
    ${statCard("Economy Gold", `${Math.round(Number(summary.totalCopper || 0) / 10000).toLocaleString()}g`, "on characters")}
  </section>

  <section class="panel realm-faction-panel">
    <div class="panel-head"><h2>Faction Balance</h2><span>${alliancePct}% Alliance / ${hordePct}% Horde</span></div>
    <div class="faction-balance">
      <div><strong class="alliance">${alliance.toLocaleString()}</strong><span>Alliance</span></div>
      <div><strong class="horde">${horde.toLocaleString()}</strong><span>Horde</span></div>
    </div>
    <div class="faction-bar"><i class="alliance" style="width:${alliancePct}%"></i><i class="horde" style="width:${hordePct}%"></i></div>
  </section>

  <section class="stats-grid realm-location-grid">
    ${statCard("Out in the world", location("Out in the world").toLocaleString(), "questing and traveling")}
    ${statCard("Cities", location("Cities").toLocaleString(), "capital hubs")}
    ${statCard("Dungeons", location("Dungeons").toLocaleString(), "instance maps")}
    ${statCard("Raids", location("Raids").toLocaleString(), "raid maps")}
    ${statCard("Battlegrounds", location("Battlegrounds").toLocaleString(), "PvP maps")}
    ${statCard("World/Random", keyedCount(realmData.accountRows, "bucket", "World/random").toLocaleString(), `${accountTotal.toLocaleString()} online tracked`)}
  </section>

  <section class="panel-grid">
    <article class="panel">
      <div class="panel-head"><h2>Zone Population Info</h2><span>Top online zones</span></div>
      ${renderPopulationBars(realmData.topZones, Math.max(1, onlineNow), { label: row => zoneLabel(row.zone, row.zoneName) || mapLabel(row.map), color: () => "#78bfe8" })}
    </article>
    ${renderWorldBossPanel(realmData.worldBosses)}
    <article class="panel">
      <div class="panel-head"><h2>Level Spread</h2><span>All characters</span></div>
      ${renderPopulationBars(realmData.levelRows, Math.max(1, totalCharacters), { label: row => row.bracket, color: () => "#8eb178" })}
    </article>
    <article class="panel">
      <div class="panel-head"><h2>Classes</h2><span>Roster makeup</span></div>
      ${renderPopulationBars(realmData.classRows, Math.max(1, totalCharacters), { label: row => classNames[Number(row.class)] || `Class ${row.class}`, color: row => classColors[Number(row.class)] || "#78bfe8" })}
    </article>
    <article class="panel">
      <div class="panel-head"><h2>Races</h2><span>Population identity</span></div>
      ${renderPopulationBars(realmData.raceRows, Math.max(1, totalCharacters), { label: row => raceNames[Number(row.race)] || `Race ${row.race}`, color: row => [2,5,6,8,10].includes(Number(row.race)) ? "#c86058" : "#5f8fd5" })}
    </article>
  </section>

  <section class="panel-grid">
    ${renderAdminActionHistory(realmData.activity)}
    <article class="panel">
      <div class="panel-head"><h2>Top PvP</h2><span>Honor, then kills</span></div>
      <table>
        <thead><tr><th>Name</th><th>Spec</th><th>Level</th><th>Honor</th><th>Kills</th></tr></thead>
        <tbody>
          ${portalData.topPvp.map(row => `<tr><td><span class="name-with-icon">${classBadge(row.class)}${escapeHtml(row.name)}</span></td><td>${escapeHtml(row.specName || "No Spec")}</td><td>${row.level}</td><td>${Number(row.totalHonorPoints).toLocaleString()}</td><td>${Number(row.totalKills).toLocaleString()}</td></tr>`).join("")}
        </tbody>
      </table>
    </article>
    <article class="panel">
      <div class="panel-head"><h2>Realm Signals</h2><span>Current portal snapshot</span></div>
      <div class="health-check-list">
        <div><strong>Worldserver</strong><span>${portalData.serverInfo !== "SOAP unavailable" ? "SOAP responding" : "SOAP unavailable"}</span></div>
        <div><strong>Auction House</strong><span>${Number(portalData.counts.ahCount || 0).toLocaleString()} live listings</span></div>
        <div><strong>Top PvP</strong><span>${escapeHtml(portalData.topPvp[0]?.name || "No ranked character found")}</span></div>
        <div><strong>Generated</strong><span>${escapeHtml(formatPortalDate(portalData.generatedAt))}</span></div>
      </div>
    </article>
  </section>`;
}

function renderAdminHealthPage(data, health) {
  const realm = realmInfoParts(data.serverInfo);
  const realmOnline = data.serverInfo !== "SOAP unavailable";
  const cpuPct = cpuPressure(data);
  const memoryPct = memoryPercent(data);
  const tickMs = parseMilliseconds(realm.updateDiff);
  const verdict = healthVerdict({ cpuPct, memoryPct, dbLatencyMs: health.dbLatencyMs, tickMs, realmOnline });
  const totalBots = Number(data.counts.onlineChars || 0);
  const worldBots = Number(health.botAccounts.find(row => row.bucket === "World/random")?.count || 0);
  const controlledBots = Number(health.botAccounts.find(row => row.bucket === "GM accounts")?.count || 0);
  const ahTotal = Number(data.counts.ahCount || 0);
  const level5065 = health.ahByLevel.filter(row => ["50-59", "60-66"].includes(row.bracket)).reduce((sum, row) => sum + Number(row.count || 0), 0);
  const gear5065 = health.ahGearByQuality.reduce((sum, row) => sum + Number(row.count || 0), 0);

  return `<section class="page-head character-lookup-head">
    <div>
      <p class="eyebrow">Admin Health</p>
      <h1>AzerothCore Health</h1>
      <p class="hero-copy">A practical lag and population dashboard for the realm, playerbots, auctions, and portal-visible system signals.</p>
    </div>
    <a class="button ghost back-button" href="/admin"><span>Back</span></a>
  </section>

  <section class="health-verdict ${healthStatusClass(verdict.status)}">
    <div>
      <span>Realm Verdict</span>
      <h2>${escapeHtml(verdict.status)}</h2>
      <p>${escapeHtml(verdict.summary)}</p>
    </div>
    <div class="health-verdict-list">
      ${verdict.warnings.length ? verdict.warnings.map(warning => `<span>${escapeHtml(warning)}</span>`).join("") : `<span>No action required.</span>`}
      <span>Health query generated in ${Number(health.generatedMs).toLocaleString()} ms.</span>
    </div>
  </section>

  <section class="health-metric-grid">
    ${healthMetric("World Tick", realm.updateDiff, realmOnline ? "SOAP server info" : "SOAP unavailable", tickMs >= 250 ? "watch" : "good")}
    ${healthMetric("CPU Pressure", `${cpuPct}%`, `${data.system.cpuCount} threads visible`, cpuPct >= 85 ? "watch" : "good")}
    ${healthMetric("Memory", `${memoryPct}%`, `${Math.round((data.system.memoryTotal - data.system.memoryFree) / 1024 / 1024 / 1024)} / ${Math.round(data.system.memoryTotal / 1024 / 1024 / 1024)} GiB`, memoryPct >= 88 ? "watch" : "good")}
    ${healthMetric("Database Ping", `${health.dbLatencyMs} ms`, "Portal to MariaDB", health.dbLatencyMs >= 150 ? "watch" : "good")}
    ${healthMetric("Online Population", totalBots.toLocaleString(), `${controlledBots} controlled / ${worldBots} world`, "good")}
    ${healthMetric("Auction House", ahTotal.toLocaleString(), `${level5065.toLocaleString()} listings level 50-66`, ahTotal < 50000 ? "watch" : "good")}
  </section>

  <section class="panel-grid health-panel-grid">
    <article class="panel">
      <div class="panel-head"><h2>Bottleneck Synthesizer</h2><span>Lag triage</span></div>
      <div class="health-check-list">
        <div><strong>World Thread</strong><span>${tickMs ? `${Math.round(tickMs)} ms update diff` : escapeHtml(realm.updateDiff)}</span></div>
        <div><strong>CPU</strong><span>${cpuPct}% pressure from load average</span></div>
        <div><strong>Database</strong><span>${health.dbLatencyMs} ms simple query</span></div>
        <div><strong>Grid Saturation</strong><span>${health.topZones.length ? `${Number(health.topZones[0].count).toLocaleString()} players/bots max zone` : "No active zones"}</span></div>
      </div>
    </article>

    <article class="panel">
      <div class="panel-head"><h2>Playerbot Hive</h2><span>Online population shape</span></div>
      <div class="health-split">
        <strong>${totalBots.toLocaleString()}</strong>
        <span>online characters and bots</span>
      </div>
      ${renderHealthBars(health.botAccounts, totalBots, "bucket")}
    </article>

    <article class="panel">
      <div class="panel-head"><h2>Top Active Zones</h2><span>Where the world is busy</span></div>
      <div class="health-zone-list">
        ${health.topZones.map(row => `<div><strong>${escapeHtml(zoneLabel(row.zone, row.zoneName) || mapLabel(row.map))}</strong><span>${escapeHtml(mapLabel(row.map))}</span><b>${Number(row.count).toLocaleString()}</b></div>`).join("") || `<p class="muted">No online characters found.</p>`}
      </div>
    </article>

    <article class="panel">
      <div class="panel-head"><h2>Bot Level Distribution</h2><span>Live online by faction</span></div>
      ${renderHealthBars(health.onlineByFactionLevel.map(row => ({ ...row, bracket: `${row.faction} ${row.bracket}` })), totalBots)}
    </article>

    <article class="panel">
      <div class="panel-head"><h2>Auction House Economy</h2><span>Stock depth</span></div>
      ${renderHealthBars(health.ahByHouse.map(row => ({ ...row, house: houseName(row.houseid) })), ahTotal, "house")}
      <div class="health-subhead">Level Brackets</div>
      ${renderHealthBars(health.ahByLevel, ahTotal)}
      <div class="health-subhead">Level 50-65 Gear Quality</div>
      <div class="ah-tags">${health.ahGearByQuality.map(row => `<span class="q${Number(row.quality)}">${escapeHtml(qualityName(row.quality))} <b>${Number(row.count || 0).toLocaleString()}</b></span>`).join("") || `<span>No 50-65 gear rows</span>`}</div>
    </article>

    <article class="panel">
      <div class="panel-head"><h2>Source & Updates</h2><span>Safe live policy</span></div>
      <div class="health-check-list">
        <div><strong>Live Updates</strong><span>Manual only. No one-click live updater.</span></div>
        <div><strong>Worldserver</strong><span>${realmOnline ? "SOAP responding" : "SOAP unavailable"}</span></div>
        <div><strong>Portal</strong><span>Serving this dashboard</span></div>
        <div><strong>Next Step</strong><span>Add host telemetry later if you want disk latency and git commit status in-page.</span></div>
      </div>
    </article>
  </section>`;
}

function formatPortalDate(value) {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return date.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit"
  });
}

function formatTimeUntil(unixSeconds) {
  const seconds = Math.max(0, Number(unixSeconds || 0) - Math.floor(Date.now() / 1000));
  if (!seconds) return "Available now";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${Math.max(1, minutes)}m`;
}

function formatLootTime(value) {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return date.toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit"
  });
}

function qualityClass(quality) {
  return `q${Number(quality || 0)}`;
}

function qualityName(quality) {
  return qualityNames[Number(quality)] || `Quality ${quality}`;
}

function wowheadItemUrl(entry) {
  return `https://www.wowhead.com/wotlk/item=${Number(entry)}`;
}

function wowheadItemAttrs(entry) {
  const itemEntry = Number(entry);
  return `href="${wowheadItemUrl(itemEntry)}" data-wowhead="item=${itemEntry}&amp;domain=wrath" target="_blank" rel="noreferrer"`;
}

function renderWowheadItemLink({ entry, name, quality, className = "", content = null }) {
  const itemEntry = Number(entry);
  const itemName = name || `Item ${itemEntry}`;
  const classes = [qualityClass(quality), className].filter(Boolean).join(" ");
  return `<a class="${escapeHtml(classes)}" ${wowheadItemAttrs(itemEntry)}>${content || escapeHtml(itemName)}</a>`;
}

function characterLookupUrl(name) {
  return `/admin/character?q=${encodeURIComponent(String(name || ""))}`;
}

function renderCharacterLookupLink(name, classId = null) {
  const characterName = String(name || "Unknown");
  const className = ["class-name", classSlugForId(classId)].filter(Boolean).join(" ");
  const color = classColors[Number(classId)] || "";
  const style = color ? ` style="color: ${color} !important"` : "";
  return `<a class="${escapeHtml(className)}" href="${characterLookupUrl(characterName)}"${style}><span class="class-name-text"${style}>${escapeHtml(characterName)}</span></a>`;
}

function raidNameForMap(mapId) {
  return raidMapNames[Number(mapId)] || `Map ${Number(mapId || 0)}`;
}

function raidRunTitle(run) {
  const worldBoss = worldBossForRun(run);
  if (worldBoss) return `${worldBoss.name} World Boss Loot`;
  return `${raidNameForMap(run.mapId)} Loot`;
}

function classSlugForId(classId) {
  return classSlugs[Number(classId)] || "";
}

function lootStatIcon(kind, label) {
  const safeKind = String(kind || "").replace(/[^a-z0-9-]/gi, "").toLowerCase();
  return `<img class="loot-stat-icon" src="/portal-art/stat-${safeKind}.png" alt="${escapeHtml(label)}">`;
}

function raidRunIcon(run = {}) {
  const worldBoss = worldBossForRun(run);
  if (worldBoss?.icon) {
    return `<img class="raid-run-icon world-boss-run-icon" src="${worldBoss.icon}" alt="${escapeHtml(worldBoss.name)}">`;
  }

  const mapId = Number(run.mapId || run.map_id || 0);
  const name = String(run.instanceName || raidNameForMap(mapId) || "").toLowerCase();
  let icon = "";
  let label = "";

  if (mapId === 409 || name.includes("molten core")) {
    icon = "/portal-art/boss-fire-lord.png";
    label = "Molten Core";
  } else if (mapId === 309 || name.includes("zul'gurub") || name.includes("zulgurub")) {
    icon = "/portal-art/boss-raid-generic.png";
    label = "Zul'Gurub";
  } else if (mapId === 509 || name.includes("aq20") || name.includes("ruins of ahn")) {
    icon = "/portal-art/boss-raid-generic.png";
    label = "AQ20";
  } else if (mapId === 469 || name.includes("blackwing") || name.includes("bwl")) {
    icon = "/portal-art/boss-dragon-blue.png";
    label = "Blackwing Lair";
  }

  return icon
    ? `<img class="raid-run-icon" src="${icon}" alt="${escapeHtml(label)}">`
    : `<span class="raid-run-icon raid-run-icon-empty" aria-hidden="true"></span>`;
}

function runTechnicalNote(run) {
  const dateText = run.lootDate ? ` - ${escapeHtml(run.lootDate)}` : "";
  const worldBoss = worldBossForRun(run);
  if (worldBoss) {
    return `${escapeHtml(worldBoss.location)}${dateText}`;
  }
  return `Run ${escapeHtml(run.sourceRunKey || run.runKey)}${dateText} - instance ${Number(run.instanceId || 0)}`;
}

function qualitySummary(drops) {
  const counts = qualityCounts(drops);

  const parts = [];
  if (counts.epic) parts.push(`${counts.epic} epic${counts.epic === 1 ? "" : "s"}`);
  if (counts.rare) parts.push(`${counts.rare} rare${counts.rare === 1 ? "" : "s"}`);
  if (counts.legendary) parts.push(`${counts.legendary} legendary`);
  return parts.length ? parts.join(" / ") : `${counts.total} tracked drop${counts.total === 1 ? "" : "s"}`;
}

function qualityCounts(drops) {
  return drops.reduce((summary, drop) => {
    const quality = Number(drop.quality || drop.item_quality || 0);
    summary.total += 1;
    if (quality === 3) summary.rare += 1;
    if (quality === 4) summary.epic += 1;
    if (quality >= 5) summary.legendary += 1;
    return summary;
  }, { total: 0, rare: 0, epic: 0, legendary: 0 });
}

function renderLootItem(drop) {
  return `<div class="loot-drop ${qualityClass(drop.quality)}">
    <div>
      ${renderWowheadItemLink({ entry: drop.itemEntry, name: drop.itemName, quality: drop.quality, content: `<strong>${escapeHtml(drop.itemName)}</strong>` })}
      <span>${escapeHtml(qualityName(drop.quality))} - item ${Number(drop.itemEntry)}${Number(drop.quantity || 1) > 1 ? ` x${Number(drop.quantity)}` : ""}</span>
    </div>
    <div class="loot-recipient">
      <span>Received by</span>
      <strong>${renderCharacterLookupLink(drop.recipientName, drop.recipientClass)}</strong>
    </div>
  </div>`;
}

function renderServerLootItem(drop) {
  return `<div class="loot-drop server-loot-drop ${qualityClass(drop.quality)}">
    <div class="loot-item-main">
      ${renderWowheadItemLink({ entry: drop.itemEntry, name: drop.itemName, quality: drop.quality, content: `<strong>${escapeHtml(drop.itemName)}</strong>` })}
      <span>${escapeHtml(qualityName(drop.quality))}${Number(drop.itemLevel || 0) ? ` - iLvl ${Number(drop.itemLevel)}` : ""}${Number(drop.quantity || 1) > 1 ? ` - x${Number(drop.quantity)}` : ""}</span>
    </div>
    <div class="loot-recipient">
      <span>${escapeHtml(formatLootTime(drop.lootedAt))}</span>
      <strong>${renderCharacterLookupLink(drop.recipientName, drop.recipientClass)}</strong>
    </div>
  </div>`;
}

function renderServerLootRuns(serverLoot) {
  if (!serverLoot?.installed) {
    return `<article class="panel loot-run-panel">
      <div class="panel-head"><h2>Raid Loot</h2><span>Not ready</span></div>
      <p class="muted">Loot tracking is not active yet.</p>
    </article>`;
  }

  const runs = serverLoot.runs || [];
  return `<article class="panel loot-run-panel server-loot-panel">
    <div class="panel-head"><h2>Raid Loot</h2><span>${runs.length} run${runs.length === 1 ? "" : "s"}</span></div>
    ${runs.length ? `<div class="loot-run-list">
      ${runs.map(run => `<a class="loot-run-card server-run-card" href="/admin/loot/server/${encodeURIComponent(run.serverRunKey || run.runKey)}">
        ${raidRunIcon(run)}
        <div class="loot-run-copy">
          <strong>${escapeHtml(raidRunTitle(run))}</strong>
          <span>${escapeHtml(formatPortalDate(run.startedAt))}</span>
          <small>${runTechnicalNote(run)}</small>
        </div>
        <dl>
          <div class="loot-stat drops">${lootStatIcon("drops", "Drops")}<dt>Drops</dt><dd>${Number(run.dropCount || 0)}</dd></div>
          <div class="loot-stat rare">${lootStatIcon("rare", "Rare")}<dt>Rare</dt><dd>${Number(run.rareCount || 0)}</dd></div>
          <div class="loot-stat epic">${lootStatIcon("epic", "Epic")}<dt>Epic</dt><dd>${Number(run.epicCount || 0)}</dd></div>
          <div class="loot-stat legendary">${lootStatIcon("legendary", "Legendary")}<dt>Legendary</dt><dd>${Number(run.legendaryCount || 0)}</dd></div>
          <div class="loot-stat looters">${lootStatIcon("looters", "Looters")}<dt>Looters</dt><dd>${Number(run.looterCount || 0)}</dd></div>
        </dl>
      </a>`).join("")}
    </div>` : `<p class="muted">No raid loot has been recorded yet. The next rare-or-better raid drop will start a run here.</p>`}
  </article>`;
}

function renderRaidLootRuns(runs, serverLoot) {
  return `<section class="page-head loot-history-head">
    <div>
      <p class="eyebrow">Raid History</p>
      <h1>Raid Loot</h1>
      <p class="hero-copy">Rare, epic, and legendary drops recorded from your runs.</p>
    </div>
    <a class="button ghost back-button" href="/admin"><span>Back</span></a>
  </section>
  ${renderServerLootRuns(serverLoot)}
  ${runs.length ? `<article class="panel loot-run-panel">
    <div class="panel-head"><h2>Launcher Uploads</h2><span>${runs.length} tracked run${runs.length === 1 ? "" : "s"}</span></div>
    ${runs.length ? `<div class="loot-run-list">
      ${runs.map(run => `<a class="loot-run-card" href="/admin/loot/${Number(run.id)}">
        ${raidRunIcon(run)}
        <div class="loot-run-copy">
          <strong>${escapeHtml(run.instanceName)}</strong>
          <span>${escapeHtml(formatPortalDate(run.startedAt))}${run.difficulty ? ` - ${escapeHtml(run.difficulty)}` : ""}</span>
        </div>
        <dl>
          <div><dt>Bosses</dt><dd>${Number(run.bossCount || 0)}</dd></div>
          <div><dt>Drops</dt><dd>${Number(run.dropCount || 0)}</dd></div>
          <div><dt>Rare</dt><dd>${Number(run.rareCount || 0)}</dd></div>
          <div><dt>Epic</dt><dd>${Number(run.epicCount || 0)}</dd></div>
          <div><dt>Legendary</dt><dd>${Number(run.legendaryCount || 0)}</dd></div>
        </dl>
      </a>`).join("")}
    </div>` : ""}
  </article>` : ""}`;
}

function renderServerRaidLootRunDetail(detail) {
  if (!detail) {
    return `<section class="page-head"><h1>Server Loot Run Not Found</h1><a class="button ghost back-button" href="/admin/loot"><span>Back</span></a></section>
      <article class="panel"><p class="muted">That raid run does not exist.</p></article>`;
  }

  const recipients = new Set(detail.drops.map(drop => drop.recipientName).filter(Boolean));
  const counts = qualityCounts(detail.drops);
  const worldBoss = worldBossForRun(detail.run);
  const kills = detail.worldBossKills || [];

  return `<section class="page-head">
    <div>
      <p class="eyebrow">${worldBoss ? "World Boss Loot" : "Raid Loot"}</p>
      <h1>${escapeHtml(raidRunTitle(detail.run))}</h1>
      <p class="hero-copy">${escapeHtml(formatPortalDate(detail.run.startedAt))} - ${qualitySummary(detail.drops)} - ${recipients.size} character${recipients.size === 1 ? "" : "s"} received loot.</p>
    </div>
    <a class="button ghost" href="/admin/loot">All Loot</a>
  </section>
  <section class="loot-summary-grid">
    <article class="loot-summary-card loot-stat-card drops">${lootStatIcon("drops", "Drops")}<span>Drops</span><strong>${Number(detail.run.dropCount || detail.drops.length || 0)}</strong></article>
    <article class="loot-summary-card loot-stat-card epic">${lootStatIcon("epic", "Epics")}<span>Epics</span><strong>${counts.epic}</strong></article>
    <article class="loot-summary-card loot-stat-card rare">${lootStatIcon("rare", "Rares")}<span>Rares</span><strong>${counts.rare}</strong></article>
    <article class="loot-summary-card loot-stat-card looters">${lootStatIcon("looters", "Looters")}<span>Looters</span><strong>${recipients.size}</strong></article>
  </section>
  ${worldBoss ? `<article class="panel world-boss-kill-panel">
    <div class="panel-head"><h2>Boss Kill</h2><span>${kills.length ? `${kills.length} recorded` : "Waiting for kill event"}</span></div>
    ${kills.length ? `<div class="world-boss-kill-list">
      ${kills.map(kill => `<div class="world-boss-kill-row">
        ${raidRunIcon({ sourceRunKey: kill.runKey, runKey: kill.runKey })}
        <div>
          <strong>${escapeHtml(kill.bossName || worldBoss.name)}</strong>
          <span>${escapeHtml(worldBoss.location)} - ${escapeHtml(formatPortalDate(kill.killedAt))}</span>
        </div>
        <div class="loot-recipient">
          <span>Killing blow</span>
          <strong>${renderCharacterLookupLink(kill.killerName, kill.killerClass)}</strong>
        </div>
      </div>`).join("")}
    </div>` : `<p class="muted">The kill hook is active. The next ${escapeHtml(worldBoss.name)} kill will be recorded here.</p>`}
  </article>` : ""}
  <article class="panel loot-detail-panel">
    <div class="panel-head"><h2>Loot Timeline</h2><span>${detail.drops.length} item${detail.drops.length === 1 ? "" : "s"}</span></div>
    <div class="loot-drop-list raid-loot-timeline">${detail.drops.length ? detail.drops.map(renderServerLootItem).join("") : `<p class="muted">No rare-or-better loot has been recorded for this kill yet.</p>`}</div>
  </article>`;
}

function renderRaidLootRunDetail(detail) {
  if (!detail) {
    return `<section class="page-head"><h1>Loot Run Not Found</h1><a class="button ghost back-button" href="/admin/loot"><span>Back</span></a></section>
      <article class="panel"><p class="muted">That tracked raid run does not exist.</p></article>`;
  }

  const dropsByBoss = new Map();
  const unassigned = [];
  for (const drop of detail.drops) {
    const bossId = Number(drop.bossId || 0);
    if (!bossId) {
      unassigned.push(drop);
      continue;
    }
    if (!dropsByBoss.has(bossId)) dropsByBoss.set(bossId, []);
    dropsByBoss.get(bossId).push(drop);
  }

  return `<section class="page-head">
    <div>
      <p class="eyebrow">Loot Run</p>
      <h1>${escapeHtml(detail.run.instanceName)}</h1>
      <p class="hero-copy">${escapeHtml(formatPortalDate(detail.run.startedAt))}${detail.run.difficulty ? ` - ${escapeHtml(detail.run.difficulty)}` : ""}${detail.run.uploadedBy ? ` - uploaded by ${escapeHtml(detail.run.uploadedBy)}` : ""}</p>
    </div>
    <a class="button ghost" href="/admin/loot">All Runs</a>
  </section>
  <article class="panel loot-detail-panel">
    <div class="panel-head"><h2>Boss Drops</h2><span>${detail.drops.length} tracked item${detail.drops.length === 1 ? "" : "s"}</span></div>
    <div class="boss-loot-list">
      ${detail.bosses.map(boss => {
        const drops = dropsByBoss.get(Number(boss.id)) || [];
        return `<section class="boss-loot-card">
          <div class="boss-loot-head">
            <div>
              <strong>${escapeHtml(boss.bossName)}</strong>
              <span>${escapeHtml(formatPortalDate(boss.killedAt))}${boss.bossEntry ? ` - NPC ${Number(boss.bossEntry)}` : ""}</span>
            </div>
            <b>${drops.length} drop${drops.length === 1 ? "" : "s"}</b>
          </div>
          ${drops.length ? `<div class="loot-drop-list">${drops.map(renderLootItem).join("")}</div>` : `<p class="muted">No rare-or-better loot recorded for this boss.</p>`}
        </section>`;
      }).join("")}
      ${unassigned.length ? `<section class="boss-loot-card">
        <div class="boss-loot-head"><div><strong>Unassigned Loot</strong><span>Uploaded without a boss match</span></div><b>${unassigned.length} drop${unassigned.length === 1 ? "" : "s"}</b></div>
        <div class="loot-drop-list">${unassigned.map(renderLootItem).join("")}</div>
      </section>` : ""}
    </div>
  </article>`;
}

function portalSnapshotForAdvisor(data) {
  const realm = realmInfoParts(data.serverInfo);
  const memoryUsed = data.system.memoryTotal - data.system.memoryFree;
  return {
    capturedAt: new Date().toISOString(),
    realm,
    counts: data.counts,
    system: {
      cpuThreads: data.system.cpuCount,
      cpuPressurePercent: cpuPressure(data),
      loadAverage: data.system.load,
      memoryPercent: memoryPercent(data),
      memoryUsedGiB: Math.round(memoryUsed / 1024 / 1024 / 1024),
      memoryTotalGiB: Math.round(data.system.memoryTotal / 1024 / 1024 / 1024),
      portalUptimeHours: Math.floor(data.system.uptime / 3600)
    },
    onlineByLevel: data.onlineByLevel,
    ahByQuality: data.ahByQuality
  };
}

function parseAdvisorStdout(stdout) {
  try {
    return JSON.parse(stdout);
  } catch {
    return null;
  }
}

function renderAdvisorJsonCard(parsed) {
  if (!parsed || typeof parsed !== "object") return "";
  const list = value => Array.isArray(value) && value.length
    ? `<ul>${value.map(item => `<li>${escapeHtml(String(item))}</li>`).join("")}</ul>`
    : `<p class="muted">None.</p>`;
  const questionList = Array.isArray(parsed.follow_up_questions) && parsed.follow_up_questions.length
    ? parsed.follow_up_questions
    : (Array.isArray(parsed.required_facts) ? parsed.required_facts.map(fact => {
        const text = String(fact).trim();
        if (!text) return "";
        return text.endsWith("?") ? text : `Can you provide ${text.charAt(0).toLowerCase()}${text.slice(1)}?`;
      }).filter(Boolean) : []);
  const hasStandardShape = "summary" in parsed || "required_facts" in parsed || "steps" in parsed || "verification" in parsed || "rollback" in parsed || "follow_up_questions" in parsed;
  const detailSections = [
    ["What I would do", parsed.steps],
    ["How I would verify it", parsed.verification],
    ["Backout plan", parsed.rollback]
  ];

  return `<div class="advisor-answer-card">
    <div class="advisor-answer-top">
      <span class="result-kicker">Advisor Reply</span>
      <strong>${escapeHtml(parsed.risk || "UNKNOWN")}</strong>
    </div>
    <section class="advisor-primary-reply">
      <h3>Answer</h3>
      <p>${escapeHtml(parsed.summary || (hasStandardShape ? "No summary returned." : "Advisor returned non-standard JSON. Raw JSON is shown below."))}</p>
    </section>
    ${renderAdvisorProposedAction(parsed)}
    ${questionList.length ? `<section class="advisor-followups">
      <h3>Follow-up Questions</h3>
      <p class="muted">Answer any of these in the question box above and ask the advisor again.</p>
      <ol>${questionList.map(question => `<li>${escapeHtml(String(question))}</li>`).join("")}</ol>
    </section>` : `<section class="advisor-followups quiet">
      <h3>Follow-up Questions</h3>
      <p>No follow-up needed from you right now.</p>
    </section>`}
    ${hasStandardShape ? `<details class="advisor-technical-details">
      <summary>Implementation details</summary>
      <div class="advisor-detail-list">
        ${detailSections.map(([title, value]) => `<section><h3>${escapeHtml(title)}</h3>${list(value)}</section>`).join("")}
      </div>
    </details>` : `<pre class="advisor-json-dump">${escapeHtml(JSON.stringify(parsed, null, 2))}</pre>`}
  </div>`;
}

function renderAdvisorProposedAction(parsed) {
  const proposed = parsed.proposed_action;
  if (!proposed || typeof proposed !== "object") return "";
  const actionKey = String(proposed.action || "");
  const tool = adminActionMap.get(actionKey);
  if (!tool) return "";

  const params = proposed.params && typeof proposed.params === "object" ? proposed.params : {};
  const missing = tool.fields.filter(field => field.required && !String(params[field.name] || "").trim());
  if (missing.length) {
    return `<section class="advisor-proposed-action blocked">
      <div>
        <span class="result-kicker">Proposed Admin Action</span>
        <h3>${escapeHtml(tool.label)}</h3>
        <p>Missing required field${missing.length === 1 ? "" : "s"}: ${missing.map(field => escapeHtml(field.label)).join(", ")}.</p>
      </div>
    </section>`;
  }

  const hiddenFields = tool.fields.map(field => `<input type="hidden" name="${escapeHtml(field.name)}" value="${escapeHtml(String(params[field.name] || ""))}">`).join("");
  const paramRows = tool.fields.length
    ? tool.fields.map(field => `<div><span>${escapeHtml(field.label)}</span><strong>${escapeHtml(String(params[field.name] || "Not set"))}</strong></div>`).join("")
    : `<div><span>Fields</span><strong>None</strong></div>`;

  return `<section class="advisor-proposed-action">
    <div>
      <span class="result-kicker">Proposed Admin Action</span>
      <h3>${escapeHtml(tool.label)}</h3>
      <p>${escapeHtml(tool.description)}</p>
      <div class="advisor-proposed-fields">${paramRows}</div>
    </div>
    <form action="/admin/advisor/execute" method="post">
      <input type="hidden" name="action" value="${escapeHtml(actionKey)}">
      ${hiddenFields}
      <button type="submit">Run Approved Admin Action</button>
    </form>
  </section>`;
}

function renderAdvisorCharacterFacts(characterFacts = []) {
  if (!characterFacts.length) return "";
  return `<article class="panel advisor-character-facts">
    <div class="panel-head">
      <h2>Attached Character Facts</h2>
      <span>${characterFacts.length} character${characterFacts.length === 1 ? "" : "s"} matched from the request</span>
    </div>
    ${characterFacts.map(character => `<section class="advisor-character-card">
      <div class="advisor-character-head">
        <div>
          <span class="result-kicker">Character</span>
          <h3>${escapeHtml(character.name)} <small>GUID ${Number(character.guid)}</small></h3>
        </div>
        <strong>Level ${Number(character.level)}</strong>
      </div>
      <div class="advisor-character-stats">
        <div><span>Account</span><strong>${escapeHtml(character.account)}</strong></div>
        <div><span>Online</span><strong>${character.online ? "Yes" : "No"}</strong></div>
        <div><span>Backpack</span><strong>${Number(character.inventorySummary.backpackFree)} free / 16</strong></div>
        <div><span>Total Rows</span><strong>${Number(character.inventorySummary.totalRows)}</strong></div>
      </div>
      <div class="advisor-bag-summary">
        ${character.inventorySummary.equippedBags.map(bag => `<div><span>${escapeHtml(bag.name)}</span><strong>${Number(bag.free)} free / ${Number(bag.slots)}</strong></div>`).join("")}
      </div>
      <details>
        <summary>Inventory rows</summary>
        <div class="advisor-inventory-list">
          ${character.inventory.map(item => `<div class="q${Number(item.quality)}">
            <span>${escapeHtml(item.location)} ${Number(item.slot)}</span>
            ${renderWowheadItemLink({ entry: item.entry, name: item.name, quality: item.quality, content: `<strong>${escapeHtml(item.name)}${Number(item.count) > 1 ? ` x${Number(item.count)}` : ""}</strong>` })}
            <small>Entry ${Number(item.entry)} - ilvl ${Number(item.itemLevel)}${item.soulbound ? " - soulbound" : ""}</small>
          </div>`).join("")}
        </div>
      </details>
    </section>`).join("")}
  </article>`;
}

function renderAdvisorSpellFacts(spellFacts = []) {
  if (!spellFacts.length) return "";
  return `<article class="panel advisor-character-facts">
    <div class="panel-head">
      <h2>Attached Spell Facts</h2>
      <span>${spellFacts.length} spell quer${spellFacts.length === 1 ? "y" : "ies"} matched from the request</span>
    </div>
    ${spellFacts.map(fact => `<section class="advisor-character-card">
      <div class="advisor-character-head">
        <div>
          <span class="result-kicker">Spell Lookup</span>
          <h3>${escapeHtml(fact.query)}</h3>
        </div>
        <strong>${fact.matches.length} match${fact.matches.length === 1 ? "" : "es"}</strong>
      </div>
      <div class="advisor-inventory-list">
        ${fact.matches.length ? fact.matches.map(spell => `<div>
          <span>${escapeHtml(spell.source)}</span>
          <strong>${escapeHtml(spell.name)}</strong>
          <small>Spell ID ${Number(spell.id)}</small>
        </div>`).join("") : `<div><span>No matches</span><strong>No spell found</strong><small>Try a more exact spell name.</small></div>`}
      </div>
      ${fact.characterKnowledge?.length ? `<div class="advisor-bag-summary">
        ${fact.characterKnowledge.map(row => `<div><span>${escapeHtml(row.name)}</span><strong>${row.knownSpells.length ? row.knownSpells.map(spell => `${escapeHtml(spell.name)} (${Number(spell.id)})`).join(", ") : "Does not know matched spell"}</strong></div>`).join("")}
      </div>` : ""}
    </section>`).join("")}
  </article>`;
}

function compactCharacterFactsForAdvisor(characterFacts = []) {
  return characterFacts.map(character => ({
    guid: character.guid,
    name: character.name,
    account: character.account,
    level: character.level,
    class: character.class,
    race: character.race,
    online: character.online,
    map: character.map,
    inventorySummary: character.inventorySummary,
    equipped: character.inventory
      .filter(item => item.location === "Equipped")
      .map(item => ({
        slot: item.slot,
        entry: item.entry,
        name: item.name,
        count: item.count,
        quality: item.quality,
        itemLevel: item.itemLevel,
        soulbound: item.soulbound,
        durability: `${item.durability}/${item.maxDurability}`
      })),
    carriedItems: character.inventory
      .filter(item => item.location !== "Equipped")
      .slice(0, 120)
      .map(item => ({
        location: item.location,
        slot: item.slot,
        entry: item.entry,
        name: item.name,
        count: item.count,
        quality: item.quality,
        itemLevel: item.itemLevel,
        soulbound: item.soulbound
      }))
  }));
}

function compactSpellFactsForAdvisor(spellFacts = []) {
  return spellFacts.map(fact => ({
    query: fact.query,
    matches: fact.matches.map(spell => ({
      id: spell.id,
      name: spell.name,
      source: spell.source
    })),
    characterKnowledge: (fact.characterKnowledge || []).map(row => ({
      guid: row.guid,
      name: row.name,
      knownSpells: row.knownSpells
    }))
  }));
}

function compactAdminActionCatalog() {
  return adminActionCatalog.map(action => ({
    action: action.action,
    label: action.label,
    description: action.description,
    fields: action.fields.map(field => ({
      name: field.name,
      required: field.required,
      type: field.type,
      options: field.options
    }))
  }));
}

function isCharacterInventoryRequest(task) {
  return /\b(inventory|inventorystate|bag|bags|backpack|carried|items|item state|current state)\b/i.test(String(task || ""));
}

const curatedSpellNames = new Map([
  [3561, "Teleport: Stormwind"],
  [3562, "Teleport: Ironforge"],
  [3563, "Teleport: Undercity"],
  [3565, "Teleport: Darnassus"],
  [3566, "Teleport: Thunder Bluff"],
  [3567, "Teleport: Orgrimmar"],
  [10059, "Portal: Stormwind"],
  [11416, "Portal: Ironforge"],
  [11417, "Portal: Orgrimmar"],
  [11418, "Portal: Undercity"],
  [11419, "Portal: Darnassus"],
  [11420, "Portal: Thunder Bluff"],
  [32266, "Portal: Exodar"],
  [32267, "Portal: Silvermoon"],
  [33690, "Teleport: Shattrath"],
  [33691, "Portal: Shattrath"],
  [35715, "Teleport: Shattrath"],
  [35717, "Portal: Shattrath"],
  [49358, "Teleport: Stonard"],
  [49359, "Teleport: Theramore"],
  [49360, "Portal: Theramore"],
  [49361, "Portal: Stonard"],
  [53140, "Teleport: Dalaran"],
  [53142, "Portal: Dalaran"]
]);

function normalizeSpellName(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .replace(/\s+/g, " ");
}

function extractSpellSearchTerms(task) {
  const text = String(task || "");
  const terms = [];
  for (const match of text.matchAll(/\b(portal|teleport)\s*:?\s*([a-z][a-z' -]{2,40})/gi)) {
    const destination = match[2].replace(/\b(and|for|from|to|on|with|please|now)\b.*$/i, "").trim();
    if (destination) terms.push(`${titleCaseName(match[1])}: ${destination.replace(/\s+/g, " ")}`);
  }
  const spellMatch = text.match(/\bspell\s+([a-z][a-z0-9:' -]{2,60})/i);
  if (spellMatch) terms.push(spellMatch[1].replace(/\b(and|for|from|to|on|with|please|now)\b.*$/i, "").trim());
  return [...new Set(terms.map(term => term.trim()).filter(Boolean))].slice(0, 5);
}

async function getAdvisorSpellFacts(task, characterFacts = []) {
  const terms = extractSpellSearchTerms(task);
  if (!terms.length) return [];

  const matchesByKey = new Map();
  for (const term of terms) {
    const normalizedTerm = normalizeSpellName(term);
    for (const [id, name] of curatedSpellNames) {
      const normalizedName = normalizeSpellName(name);
      if (normalizedName === normalizedTerm || normalizedName.includes(normalizedTerm) || normalizedTerm.includes(normalizedName)) {
        matchesByKey.set(`${term}:${id}`, { query: term, id, name, source: "curated-wotlk" });
      }
    }

    const dbRows = await query(`SELECT ID id, Name_Lang_enUS name
      FROM acore_world.spell_dbc
      WHERE Name_Lang_enUS LIKE :term
      ORDER BY ID
      LIMIT 20`, { term: `%${term}%` });

    for (const row of dbRows) {
      if (!row.name) continue;
      matchesByKey.set(`${term}:${Number(row.id)}`, { query: term, id: Number(row.id), name: row.name, source: "spell_dbc" });
    }
  }

  const matches = [...matchesByKey.values()].slice(0, 40);
  if (!matches.length) {
    return terms.map(term => ({ query: term, matches: [], characterKnowledge: [] }));
  }

  const guids = characterFacts.map(character => Number(character.guid)).filter(Number.isSafeInteger);
  const spellIds = [...new Set(matches.map(match => Number(match.id)))];
  const knownByGuidSpell = new Set();
  if (guids.length && spellIds.length) {
    const guidPlaceholders = guids.map(() => "?").join(",");
    const spellPlaceholders = spellIds.map(() => "?").join(",");
    const [knownRows] = await db.query(`SELECT guid, spell
      FROM acore_characters.character_spell
      WHERE guid IN (${guidPlaceholders})
        AND spell IN (${spellPlaceholders})`, [...guids, ...spellIds]);
    for (const row of knownRows) knownByGuidSpell.add(`${Number(row.guid)}:${Number(row.spell)}`);
  }

  return terms.map(term => {
    const termMatches = matches.filter(match => match.query === term);
    return {
      query: term,
      matches: termMatches,
      characterKnowledge: characterFacts.map(character => ({
        guid: Number(character.guid),
        name: character.name,
        knownSpells: termMatches
          .filter(match => knownByGuidSpell.has(`${Number(character.guid)}:${Number(match.id)}`))
          .map(match => ({ id: match.id, name: match.name }))
      }))
    };
  });
}

function unsupportedSpellCastIntent(task) {
  const text = String(task || "");
  const lower = text.toLowerCase();
  const wantsCast = /\b(cast|use|open|make|have|ask|tell)\b.*\b(spell|portal|teleport|conjure|buff)\b|\bportal\s*:\s*[a-z]/i.test(text);
  const teaching = /\b(learn|teach|train)\b.*\b(spell|portal)\b/i.test(text);
  const selfCastCommand = /\b(cast spell|spell cast)\b/i.test(text);
  return wantsCast && !teaching && !selfCastCommand && !/\b(add item|grant item|give item|item id|entry)\b/i.test(lower);
}

function unsupportedSpellCastResponse(task, spellFacts = []) {
  const name = String(task || "").match(/\b(?:have|ask|tell|make)\s+([a-z0-9]{3,24})\b/i)?.[1];
  const character = name ? titleCaseName(name) : "";
  const knownLines = spellFacts.flatMap(fact => fact.characterKnowledge || [])
    .filter(row => row.knownSpells?.length)
    .map(row => `${row.name} knows ${row.knownSpells.map(spell => `${spell.name} (${spell.id})`).join(", ")}.`);
  return {
    ready: false,
    risk: "MEDIUM",
    summary: character
      ? `${knownLines.length ? `${knownLines.join(" ")} ` : ""}I cannot safely make ${character} cast a spell from the current portal action catalog. I will not convert this into an item grant or another unrelated command.`
      : "I cannot safely make a character cast a spell from the current portal action catalog. I will not convert this into an item grant or another unrelated command.",
    follow_up_questions: [
      "Do you want me to design a curated Playerbot spell-cast action for portal requests, or should this stay as an in-game Playerbot command only?"
    ],
    required_facts: [
      "Exact supported Playerbot command syntax for asking a bot to cast a portal spell from outside the game client."
    ],
    steps: [
      "Do not run Grant Item, Learn Spell, or raw SOAP for this request.",
      "Confirm whether AzerothCore/Playerbots exposes a safe command path for a bot casting a portal on demand.",
      "If a safe command exists, add it as a curated portal action with explicit character and destination fields."
    ],
    verification: [
      "The current admin action catalog has Learn Spell, but not Cast Spell or Ask Bot To Cast Portal.",
      "The advisor must not map spell-casting requests to addItem."
    ],
    rollback: []
  };
}

function titleCaseName(value) {
  const clean = String(value || "").trim().replace(/[^a-z0-9]/gi, "");
  return clean ? clean.charAt(0).toUpperCase() + clean.slice(1).toLowerCase() : "";
}

function wordsFromTask(task) {
  return String(task || "").toLowerCase().match(/\b[a-z0-9]{2,32}\b/g) || [];
}

function candidateValue(task, fieldName, actionWords = []) {
  const stop = new Set([
    "run", "do", "please", "the", "for", "with", "and", "admin", "action", "check",
    "show", "get", "give", "set", "make", "use", "on", "to", "from", "my", "a", "an",
    "next", "beside", "near", "minutes", "minute", "mins", "min",
    fieldName.toLowerCase(), ...actionWords
  ]);
  const words = wordsFromTask(task).filter(word => !stop.has(word));
  return words.length ? words[words.length - 1] : "";
}

function inferAdvisorAdminAction(task) {
  const text = String(task || "").trim();
  const lower = text.toLowerCase();
  const words = new Set(wordsFromTask(text));
  const actionTests = [
    ["ahStatus", /\b(ahbot|auction\s*bot|auction\s*house|ah)\b.*\b(status|check)\b|\b(status|check)\b.*\b(ahbot|auction\s*bot|auction\s*house|ah)\b/i],
    ["ahReload", /\b(reload|refresh)\b.*\b(ahbot|auction|auctionhouse|auctions)\b/i],
    ["serverInfo", /\b(server|realm)\b.*\b(info|status|uptime)\b/i],
    ["saveAll", /\b(saveall|save all|save characters)\b/i],
    ["pinfo", /\b(character info|player info|pinfo)\b/i],
    ["revive", /\b(revive|resurrect|rez)\b/i],
    ["unstuck", /\b(unstuck|hearth|inn)\b/i],
    ["summonToCharacter", /\b(summon|bring|move)\s+[a-z0-9]{2,24}\s+(?:to|beside|near)\s+[a-z0-9]{3,24}\b|\b(summon|bring|move)\b.*\b(to|beside|near)\b.*\b(raid|group|member)\b/i],
    ["summon", /\b(summon|bring)\b/i],
    ["appear", /\b(appear|go to character|goto character)\b/i],
    ["rename", /\b(rename|flag rename)\b/i],
    ["level", /\b(set level|level)\b/i],
    ["addItem", /\b(add item|grant item|give item)\b/i],
    ["learnSpell", /\b(learn spell|teach spell)\b/i],
    ["resetTalents", /\b(reset talents|talent reset)\b/i],
    ["summonRepairBot", /\b(summon|spawn|place|create|pop)\b.*\brepair\s*bot\b|\brepair\s*bot\b.*\b(summon|spawn|place|create|pop)\b/i],
    ["repair", /\b(repair gear|repair items|repair)\b/i],
    ["setTitle", /\b(set title|give title)\b/i],
    ["botMaintenance", /\b(bot maintenance|playerbot maintenance|maintenance|maintain bot|maintain playerbot)\b/i],
    ["botReset", /\b(reset bot|bot reset|reset ai)\b/i],
    ["botSummon", /\b(summon bot|bot summon)\b/i],
    ["botDismiss", /\b(dismiss bot|bot dismiss)\b/i],
    ["raidBagCleanup", /\b(raid bag cleanup|clean bags|cleanup bags|bag cleanup|sell raid junk|sell soulbound|vendor soulbound)\b/i],
    ["accountCreate", /\b(create account|account create)\b/i],
    ["accountPassword", /\b(set password|change password|account password)\b/i],
    ["accountGm", /\b(set gm|gm level|gmlevel)\b/i],
    ["lookupItem", /\b(lookup item|item lookup|search item)\b/i],
    ["lookupCreature", /\b(lookup creature|creature lookup|search creature|lookup npc|npc lookup)\b/i],
    ["lookupQuest", /\b(lookup quest|quest lookup|search quest)\b/i],
    ["announce", /\b(announce|broadcast)\b/i],
    ["restartWarning", /\b(restart warning|restart announce)\b/i],
    ["ahRestockRange", /\b(level range|restock range|auction range|check range)\b/i]
  ];

  let actionKey = actionTests.find(([, pattern]) => pattern.test(lower))?.[0] || "";
  if (!actionKey) {
    for (const action of adminActionCatalog) {
      if (lower.includes(action.action.toLowerCase())) {
        actionKey = action.action;
        break;
      }
      const labelWords = wordsFromTask(action.label).filter(word => word.length > 2);
      if (labelWords.length && labelWords.every(word => words.has(word))) {
        actionKey = action.action;
        break;
      }
    }
  }
  if (!actionKey || !adminActionMap.has(actionKey)) return null;

  const tool = adminActionMap.get(actionKey);
  const actionWords = wordsFromTask(`${tool.action} ${tool.label}`);
  const params = {};

  for (const field of tool.fields) {
    if (field.type === "select" && field.options?.length) {
      const matched = field.options.find(option => {
        const value = typeof option === "object" ? option.value : option;
        const label = typeof option === "object" ? option.label : option;
        return lower.includes(String(value).toLowerCase()) || lower.includes(String(label).toLowerCase());
      });
      if (matched) params[field.name] = String(typeof matched === "object" ? matched.value : matched);
      continue;
    }

    if (field.type === "number") {
      const labelPattern = new RegExp(`\\b${field.name}\\b\\s*(?:to|=|:)?\\s*(\\d+)`, "i");
      const labeled = text.match(labelPattern);
      const anyNumber = text.match(/\b\d+\b/);
      if (labeled || anyNumber) params[field.name] = (labeled || anyNumber)[1] || (labeled || anyNumber)[0];
      continue;
    }

    if (field.name === "message") {
      const message = text.replace(/^\s*(announce|broadcast)\s*/i, "").trim();
      if (message) params.message = message;
      continue;
    }

    if (field.name === "term") {
      const term = text.replace(/^\s*(lookup|search)\s+(item|creature|npc|quest)\s*/i, "").trim();
      if (term) params.term = term;
      continue;
    }

    if (field.name === "character") {
      const match = text.match(/\b(?:character|player|toon|next to|beside|near|on|to)\s+([a-z0-9]{3,24})\b/i);
      params[field.name] = titleCaseName(match?.[1] || candidateValue(text, field.name, actionWords));
      continue;
    }

    if (field.name === "account") {
      const match = text.match(/\b(?:account|for)\s+([a-z0-9]{3,24})\b/i);
      params[field.name] = titleCaseName(match?.[1] || candidateValue(text, field.name, actionWords));
      continue;
    }

    if (field.name === "bot") {
      const match = text.match(/\b(?:bot|playerbot|on|for|to)\s+([a-z0-9]{3,24})\b/i);
      params[field.name] = titleCaseName(match?.[1] || candidateValue(text, field.name, actionWords));
      continue;
    }

    if (field.type === "password") continue;
    params[field.name] = candidateValue(text, field.name, actionWords);
  }

  if (actionKey === "level" && !params.level) {
    const level = text.match(/\blevel\s*(\d{1,2})\b/i);
    if (level) params.level = level[1];
  }
  if (actionKey === "addItem") {
    const numbers = text.match(/\b\d+\b/g) || [];
    if (!params.entry && numbers[0]) params.entry = numbers[0];
    if (!params.count && numbers[1]) params.count = numbers[1];
  }
  if (actionKey === "learnSpell" && !params.spell) {
    const spell = text.match(/\b\d+\b/);
    if (spell) params.spell = spell[0];
  }
  if (actionKey === "ahRestockRange") {
    const numbers = text.match(/\b\d+\b/g) || [];
    if (!params.minLevel && numbers[0]) params.minLevel = numbers[0];
    if (!params.maxLevel && numbers[1]) params.maxLevel = numbers[1];
  }
  if (actionKey === "summonRepairBot") {
    const duration = text.match(/\b(\d{1,2})\s*(?:minutes?|mins?|min)\b/i);
    if (!params.duration) params.duration = duration?.[1] || "10";
    if (!params.entry) params.entry = "24780";
  }
  if (actionKey === "summonToCharacter") {
    const toMatch = text.match(/\b(?:to|beside|near)\s+([a-z0-9]{3,24})\b/i);
    if (!params.destination && toMatch) params.destination = titleCaseName(toMatch[1]);
    const moveMatch = text.match(/\b(?:summon|bring|move)\s+([a-z0-9]{2,24})\b/i);
    const moveTarget = String(moveMatch?.[1] || "").toLowerCase();
    params.character = moveTarget && !["me", "myself"].includes(moveTarget) ? titleCaseName(moveTarget) : "Charactername";
  }
  if (actionKey === "raidBagCleanup") {
    if (!params.mode) params.mode = lower.includes("sell") || lower.includes("vendor") ? "sell" : "dry";
    if (!params.maxQuality) params.maxQuality = lower.includes("green only") ? "2" : "3";
  }

  return {
    ready: true,
    risk: "LOW",
    summary: `Matched your request to the existing admin action "${tool.label}". Review the proposed action and approve it to execute.`,
    required_facts: [],
    steps: ["Review the proposed action card.", "Click Run Approved Admin Action if the fields are correct."],
    verification: ["The action key is in the portal admin catalog.", "Execution will use the existing validated admin action path."],
    rollback: [],
    proposed_action: { action: actionKey, params }
  };
}

function renderAdminActionHistory(history = []) {
  return `<article class="panel advisor-history">
    <div class="panel-head">
      <h2>Recent Admin Actions</h2>
      <span>${history.length ? `${history.length} recent action${history.length === 1 ? "" : "s"}` : "No recorded actions yet"}</span>
    </div>
    ${history.length ? `<div class="advisor-history-list">
      ${history.map(row => {
        let params = {};
        try { params = JSON.parse(row.paramsText || "{}"); } catch {}
        const paramText = Object.entries(params).map(([key, value]) => `${key}: ${value}`).join(", ") || "No fields";
        return `<section class="${Number(row.success) ? "success" : "failed"}">
          <div>
            <strong>${escapeHtml(row.actionLabel)}</strong>
            <span>${escapeHtml(row.source)} - ${escapeHtml(new Date(row.createdAt).toLocaleString("en-US", { timeZone: "America/New_York" }))}</span>
          </div>
          <p>${escapeHtml(paramText)}</p>
          <small>${escapeHtml(row.status)}</small>
        </section>`;
      }).join("")}
    </div>` : `<p class="muted">Approved Advisor actions and standard admin actions will appear here.</p>`}
  </article>`;
}

function renderAdvisorPage({ selected = "", customTask = "", response = null, error = "", characterFacts = [], spellFacts = [], history = [] } = {}) {
  const selectedReport = advisorReports[selected];
  const parsed = response ? parseAdvisorStdout(response.stdout) : null;
  return `
    <section class="page-head">
      <h1>AzerothCore Advisor</h1>
      <a class="button ghost back-button" href="/admin"><span>Back</span></a>
    </section>
    <section class="advisor-shell">
      <article class="panel advisor-intro">
        <div class="panel-head">
          <h2>Controlled Reports</h2>
          <span>Runs through the local AI Mac with curated admin actions</span>
        </div>
        <p class="muted">The advisor can assess supplied portal facts, identify missing facts, and propose the same admin actions already available on this site. Proposed actions require a separate approval click before they run.</p>
      </article>
      <div class="advisor-loading" id="advisor-loading" role="status" aria-live="polite">
        <div><span></span></div>
        <strong>Advisor is working...</strong>
      </div>
      <div class="advisor-report-grid">
        ${Object.entries(advisorReports).map(([key, report]) => `<form class="advisor-report-card advisor-form ${selected === key ? "active" : ""}" action="/admin/advisor" method="post">
          <input type="hidden" name="report" value="${escapeHtml(key)}">
          <strong>${escapeHtml(report.label)}</strong>
          <span>${escapeHtml(report.description)}</span>
          <button type="submit">Run Report</button>
        </form>`).join("")}
      </div>
      <article class="panel advisor-custom">
        <div class="panel-head"><h2>Specific Question or Admin Task</h2><span>Advisor can propose existing admin actions</span></div>
        <form class="advisor-form" action="/admin/advisor" method="post">
          <input type="hidden" name="report" value="custom">
          <textarea name="task" rows="4" maxlength="2000" placeholder="Ask a AzerothCore-only question or task. Example: Run character info on Healername, revive Charactername, check AHBot status, or set Shamanname to level 58.">${escapeHtml(customTask)}</textarea>
          <button type="submit">Ask Advisor</button>
        </form>
      </article>
      ${error ? `<article class="panel result-panel failed"><div class="result-hero"><div><span class="result-kicker">Advisor</span><h2>Request failed</h2></div><span class="result-pill">Needs Attention</span></div><p>${escapeHtml(error)}</p></article>` : ""}
      ${renderAdvisorCharacterFacts(characterFacts)}
      ${renderAdvisorSpellFacts(spellFacts)}
      ${response ? `<article class="panel result-panel ${response.ok ? "success" : "failed"}">
        <div class="result-hero">
          <div>
            <span class="result-kicker">${escapeHtml(selectedReport?.label || "Custom Advisor Request")}</span>
            <h2>${response.ok ? "Advisor response" : "Advisor gateway error"}</h2>
          </div>
          <span class="result-pill">${response.ok ? "Complete" : "Needs Attention"}</span>
        </div>
        ${renderAdvisorJsonCard(parsed) || `<div class="command-result"><div class="command-result-head"><span>Raw advisor response</span><small>Wrapper output</small></div>${renderCommandOutput(response.stdout || response.stderr || "No output returned.")}</div>`}
      </article>` : ""}
      ${renderAdminActionHistory(history)}
    </section>
    <script>
      document.querySelectorAll(".advisor-form").forEach(form => {
        form.addEventListener("submit", () => {
          const loading = document.getElementById("advisor-loading");
          if (loading) loading.classList.add("visible");
          form.setAttribute("aria-busy", "true");
          form.querySelectorAll("button").forEach(button => {
            button.disabled = true;
            button.textContent = "Working...";
          });
        });
      });
    </script>`;
}

async function advisorGateway(mode, task) {
  const advisorUrl = process.env.ADVISOR_URL || "";
  const advisorToken = process.env.ADVISOR_TOKEN || "";
  if (!advisorUrl || !advisorToken) throw new Error("Advisor gateway is not configured.");

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Number(process.env.ADVISOR_TIMEOUT_MS || 5000));
  try {
    const response = await fetch(`${advisorUrl.replace(/\/+$/, "")}/${mode}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Advisor-Token": advisorToken
      },
      body: JSON.stringify({ task }),
      signal: controller.signal
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || payload.stderr || `Advisor gateway returned ${response.status}`);
    }
    return payload;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("Advisor gateway timed out.");
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function renderGearItem(slotInfo, item) {
  if (!item) {
    return `<section class="gear-item empty">
      <div class="gear-icon">${escapeHtml(slotInfo.label.slice(0, 2))}</div>
      <div>
        <span>${escapeHtml(slotInfo.label)}</span>
        <strong>Empty</strong>
      </div>
    </section>`;
  }

  const quality = Number(item.quality);
  const qualityClass = `q${quality}`;
  const qualityName = qualityNames[quality] || `Quality ${quality}`;
  const itemName = item.name || `Item ${item.entry}`;

  return `<a class="gear-item ${qualityClass}" ${wowheadItemAttrs(item.entry)}>
    <div class="gear-icon">${escapeHtml(slotInfo.label.slice(0, 2))}</div>
    <div>
      <span>${escapeHtml(slotInfo.label)}</span>
      <strong>${escapeHtml(itemName)}</strong>
      <small>${escapeHtml(qualityName)} · iLvl ${Number(item.itemLevel || 0).toLocaleString()}${item.requiredLevel ? ` · Req ${Number(item.requiredLevel).toLocaleString()}` : ""}</small>
    </div>
  </a>`;
}

function equippedSetSummaries(gear) {
  const sets = new Map();
  for (const item of Array.from((gear || new Map()).values())) {
    const setId = Number(item?.itemSet || 0);
    if (!setId || !item?.itemSetInfo) continue;
    if (!sets.has(setId)) {
      sets.set(setId, {
        id: setId,
        name: item.itemSetInfo.name,
        pieces: [],
        bonuses: item.itemSetInfo.bonuses || []
      });
    }
    sets.get(setId).pieces.push({
      entry: Number(item.entry),
      name: item.name || `Item ${Number(item.entry)}`
    });
  }

  return Array.from(sets.values())
    .filter(set => set.pieces.length >= 2)
    .sort((a, b) => b.pieces.length - a.pieces.length || a.name.localeCompare(b.name));
}

function renderSetBonusPanel(gear) {
  const sets = equippedSetSummaries(gear);
  if (!sets.length) return "";

  return `<article class="gear-group gear-set-group">
    <h4>Set Bonuses</h4>
    <div class="set-bonus-list">
      ${sets.map(set => `<section class="set-bonus-card">
        <div class="set-bonus-head">
          <div class="set-bonus-icon">Set</div>
          <div>
            <strong>${escapeHtml(set.name)}</strong>
            <span>${set.pieces.length} equipped piece${set.pieces.length === 1 ? "" : "s"}</span>
          </div>
        </div>
        <div class="set-piece-list">
          ${set.pieces.map(piece => `<a ${wowheadItemAttrs(piece.entry)}>${escapeHtml(piece.name)}</a>`).join("")}
        </div>
        <div class="set-threshold-list">
          ${set.bonuses.length ? set.bonuses.map(bonus => {
            const active = set.pieces.length >= Number(bonus.threshold || 0);
            return `<div class="set-threshold ${active ? "active" : "inactive"}">
              <span>${Number(bonus.threshold)}pc</span>
              <div>
                <strong>${escapeHtml(bonus.name)}</strong>
                ${bonus.description ? `<small>${escapeHtml(bonus.description)}</small>` : `<small>Spell ${Number(bonus.spellId)}</small>`}
              </div>
            </div>`;
          }).join("") : `<p class="muted">No set spell bonuses are listed for this set.</p>`}
        </div>
      </section>`).join("")}
    </div>
  </article>`;
}

function renderGearPanel(row, gearByGuid) {
  const gear = gearByGuid.get(Number(row.guid)) || new Map();
  const equippedCount = Array.from(gear.keys()).length;
  const primaryGroups = equipmentGroups.slice(0, 2);
  const sideGroup = equipmentGroups[2];
  const renderGroup = group => `<article class="gear-group">
    <h4>${escapeHtml(group.title)}</h4>
    <div class="gear-list">
      ${group.slots.map(slotInfo => renderGearItem(slotInfo, gear.get(slotInfo.slot))).join("")}
    </div>
  </article>`;

  return `<section class="gear-panel">
    <div class="gear-head">
      <div>
        <h3>Equipped Gear</h3>
        <span>${equippedCount} equipped slot${equippedCount === 1 ? "" : "s"}</span>
      </div>
      <a href="https://www.wowhead.com/wotlk" target="_blank" rel="noreferrer">WotLK Wowhead</a>
    </div>
    <div class="gear-groups">
      ${primaryGroups.map(renderGroup).join("")}
      <div class="gear-side-stack">
        ${renderGroup(sideGroup)}
        ${renderSetBonusPanel(gear)}
      </div>
    </div>
  </section>`;
}

function gearSummaryFromEquipped(gear) {
  const items = Array.from((gear || new Map()).entries())
    .filter(([slot, item]) => combatGearSlots.has(Number(slot)) && Number(item?.itemLevel || 0) > 0)
    .map(([, item]) => Number(item.itemLevel || 0));
  if (!items.length) return { averageItemLevel: 0, equippedCombatSlots: 0 };
  const totalItemLevel = items.reduce((sum, itemLevel) => sum + itemLevel, 0);
  return {
    averageItemLevel: Math.round(totalItemLevel / items.length),
    equippedCombatSlots: items.length
  };
}

function renderCharacterCards(rows, gearByGuid, specsByGuid = new Map(), options = {}) {
  const showAccount = options.showAccount !== false;
  return rows.map(row => {
    const title = titleNames[row.chosenTitle] || (row.chosenTitle ? `Title ${row.chosenTitle}` : "No title");
    const specName = specsByGuid.get(Number(row.guid)) || "Unknown";
    const gear = gearByGuid.get(Number(row.guid)) || new Map();
    const gearSummary = gearSummaryFromEquipped(gear);
    return `<section class="character-card">
      <div class="character-main">
        ${classBadge(row.class)}
        <div>
          <strong>${escapeHtml(row.name)}</strong>
          <span>${escapeHtml(title)}</span>
        </div>
        <div class="character-gear-score" title="Equipped average item level from combat gear slots">
          <span>Gear</span>
          <strong>${gearSummary.averageItemLevel ? `iLvl ${gearSummary.averageItemLevel}` : "--"}</strong>
          <small>${gearSummary.equippedCombatSlots}/17 slots</small>
        </div>
      </div>
      <dl>
        ${showAccount ? `<div><dt>Account</dt><dd>${escapeHtml(row.username)}</dd></div>` : ""}
        <div><dt>Faction</dt><dd>${factionForRace(row.race)}</dd></div>
        <div><dt>Class</dt><dd>${escapeHtml(classNames[row.class] || row.class)}</dd></div>
        <div><dt>Spec</dt><dd>${escapeHtml(specName)}</dd></div>
        <div><dt>Level</dt><dd>${row.level}</dd></div>
        <div><dt>Online</dt><dd>${row.online ? "Yes" : "No"}</dd></div>
        <div><dt>Location</dt><dd>${escapeHtml(mapLabel(row.map))}</dd></div>
        <div><dt>Honor</dt><dd>${Number(row.totalHonorPoints).toLocaleString()}</dd></div>
        <div><dt>Kills</dt><dd>${Number(row.totalKills).toLocaleString()}</dd></div>
      </dl>
      ${renderGearPanel(row, gearByGuid)}
    </section>`;
  }).join("");
}

function roleForSpec(classId, specName) {
  const className = classNames[classId] || "";
  const spec = String(specName || "").toLowerCase();
  if (spec.includes("protection") || spec.includes("blood")) return "Tank";
  if (spec.includes("holy") || spec.includes("restoration") || spec.includes("discipline")) return "Heal";
  if (className === "Druid" && spec.includes("feral")) return "Tank/DPS";
  return "DPS";
}

async function getRaidRosterRows(portalUser) {
  const baseUsername = String(portalUser?.username || "").toLowerCase();
  const raidPrefix = `${baseUsername}raid%`;
  const shortRaidPrefix = `${baseUsername}aid%`;
  const [rows] = await db.query(`SELECT
      c.guid,
      c.name,
      c.level,
      c.race,
      c.class,
      c.online,
      c.zone,
      c.map,
      c.activeTalentGroup,
      c.totalHonorPoints,
      c.totalKills,
      a.username,
      COALESCE(NULLIF(area.AreaName_Lang_enUS, ''), NULL) zoneName
    FROM acore_characters.characters c
    JOIN acore_auth.account a ON a.id = c.account
    JOIN acore_auth.portal_users pu ON pu.account_id = a.id
    LEFT JOIN acore_world.areatable_dbc area ON area.ID = c.zone
    WHERE LOWER(pu.username) = ?
       OR LOWER(pu.username) LIKE ?
       OR LOWER(pu.username) LIKE ?
    ORDER BY
      CASE WHEN LOWER(pu.username) = ? THEN 0 ELSE 1 END,
      pu.username,
      c.level DESC,
      c.name`, [baseUsername, raidPrefix, shortRaidPrefix, baseUsername]);

  const guids = rows.map(row => Number(row.guid));
  const [gearByGuid, specsByGuid] = await Promise.all([
    getEquippedGear(guids),
    getCharacterSpecs(rows)
  ]);

  return rows.map(row => {
    const gear = gearByGuid.get(Number(row.guid)) || new Map();
    const gearSummary = gearSummaryFromEquipped(gear);
    const specName = specsByGuid.get(Number(row.guid)) || "Unknown";
    return {
      ...row,
      specName,
      role: roleForSpec(Number(row.class), specName),
      averageItemLevel: gearSummary.averageItemLevel,
      equippedCombatSlots: gearSummary.equippedCombatSlots
    };
  });
}

function renderRaidRoster(rows) {
  const accountNames = [...new Set(rows.map(row => row.username))];
  const averageGear = rows.length
    ? Math.round(rows.reduce((sum, row) => sum + Number(row.averageItemLevel || 0), 0) / rows.length)
    : 0;
  const level60Count = rows.filter(row => Number(row.level) >= 60).length;
  const onlineCount = rows.filter(row => Number(row.online)).length;
  const roleCounts = rows.reduce((counts, row) => {
    counts[row.role] = (counts[row.role] || 0) + 1;
    return counts;
  }, {});
  const tankCount = Number(roleCounts.Tank || 0) + Number(roleCounts["Tank/DPS"] || 0);
  const healCount = Number(roleCounts.Heal || 0);
  const dpsCount = Number(roleCounts.DPS || 0) + Number(roleCounts["Tank/DPS"] || 0);

  return `
  <section class="page-head raid-roster-head">
    <div>
      <p class="eyebrow">Raid Operations</p>
      <h1>Raid Roster</h1>
      <p class="hero-copy">The four raid accounts in one place, with spec, role, level, online state, location, and equipped average item level.</p>
    </div>
    <a class="button ghost back-button" href="/admin"><span>Back</span></a>
  </section>
  <section class="raid-roster-summary">
    <article><span>Characters</span><strong>${rows.length.toLocaleString()}</strong><small>${level60Count.toLocaleString()} level 60+</small></article>
    <article><span>Average Gear</span><strong>${averageGear ? `iLvl ${averageGear}` : "--"}</strong><small>Equipped combat slots</small></article>
    <article><span>Online</span><strong>${onlineCount.toLocaleString()}</strong><small>Ready right now</small></article>
    <article><span>Roles</span><strong>${tankCount} / ${healCount} / ${dpsCount}</strong><small>Tank / Heal / DPS</small></article>
  </section>
  <article class="panel raid-roster-panel">
    <div class="panel-head">
      <h2>40-Man Team</h2>
      <span>${accountNames.length ? accountNames.map(account => escapeHtml(account)).join(", ") : "No linked raid accounts found"}</span>
    </div>
    <div class="raid-roster-table-wrap">
      <table class="raid-roster-table">
        <thead>
          <tr>
            <th data-sort="text">Character</th>
            <th data-sort="text">Account</th>
            <th data-sort="text">Class</th>
            <th data-sort="text">Spec</th>
            <th data-sort="text">Role</th>
            <th data-sort="number">Level</th>
            <th data-sort="number">Gear</th>
            <th data-sort="number">Slots</th>
            <th data-sort="number">Online</th>
            <th data-sort="text">Location</th>
            <th data-sort="number">Kills</th>
            <th data-sort="number">Honor</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(row => `<tr>
            <td data-sort-value="${escapeHtml(row.name)}"><a class="name-with-icon raid-roster-name" href="/admin/character?q=${encodeURIComponent(row.name)}">${classBadge(row.class)}<span>${escapeHtml(row.name)}</span></a></td>
            <td data-sort-value="${escapeHtml(row.username)}">${escapeHtml(row.username)}</td>
            <td data-sort-value="${escapeHtml(classNames[row.class] || row.class)}">${escapeHtml(classNames[row.class] || row.class)}</td>
            <td data-sort-value="${escapeHtml(row.specName)}">${escapeHtml(row.specName)}</td>
            <td data-sort-value="${escapeHtml(row.role)}"><span class="raid-role raid-role-${escapeHtml(row.role.toLowerCase().replaceAll("/", "-"))}">${escapeHtml(row.role)}</span></td>
            <td data-sort-value="${Number(row.level || 0)}">${Number(row.level).toLocaleString()}</td>
            <td data-sort-value="${Number(row.averageItemLevel || 0)}"><strong>${row.averageItemLevel ? `iLvl ${Number(row.averageItemLevel).toLocaleString()}` : "--"}</strong></td>
            <td data-sort-value="${Number(row.equippedCombatSlots || 0)}">${Number(row.equippedCombatSlots || 0)}/17</td>
            <td data-sort-value="${Number(row.online) ? 1 : 0}">${Number(row.online) ? '<span class="status-pill online">Online</span>' : '<span class="status-pill offline">Offline</span>'}</td>
            <td data-sort-value="${escapeHtml(zoneLabel(row.zone, row.zoneName) || mapLabel(row.map))}">${escapeHtml(zoneLabel(row.zone, row.zoneName) || mapLabel(row.map))}</td>
            <td data-sort-value="${Number(row.totalKills || 0)}">${Number(row.totalKills || 0).toLocaleString()}</td>
            <td data-sort-value="${Number(row.totalHonorPoints || 0)}">${Number(row.totalHonorPoints || 0).toLocaleString()}</td>
          </tr>`).join("")}
        </tbody>
      </table>
    </div>
  </article>
  <script>
    document.querySelectorAll(".raid-roster-table").forEach(table => {
      const tbody = table.querySelector("tbody");
      table.querySelectorAll("th[data-sort]").forEach((th, index) => {
        th.tabIndex = 0;
        th.setAttribute("role", "button");
        th.setAttribute("aria-sort", "none");
        th.addEventListener("click", () => sortRaidRosterTable(table, tbody, th, index));
        th.addEventListener("keydown", event => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            sortRaidRosterTable(table, tbody, th, index);
          }
        });
      });
    });

    function sortRaidRosterTable(table, tbody, th, index) {
      const type = th.dataset.sort || "text";
      const direction = th.dataset.direction === "asc" ? "desc" : "asc";
      table.querySelectorAll("th[data-sort]").forEach(header => {
        header.dataset.direction = "";
        header.setAttribute("aria-sort", "none");
      });
      th.dataset.direction = direction;
      th.setAttribute("aria-sort", direction === "asc" ? "ascending" : "descending");
      const multiplier = direction === "asc" ? 1 : -1;
      const rows = Array.from(tbody.querySelectorAll("tr"));
      rows.sort((a, b) => {
        const aValue = a.children[index]?.dataset.sortValue || a.children[index]?.textContent || "";
        const bValue = b.children[index]?.dataset.sortValue || b.children[index]?.textContent || "";
        if (type === "number") {
          return (Number(aValue) - Number(bValue)) * multiplier;
        }
        return aValue.localeCompare(bValue, undefined, { numeric: true, sensitivity: "base" }) * multiplier;
      });
      rows.forEach(row => tbody.appendChild(row));
    }
  </script>`;
}

function authPage({ mode, error = "", values = {} }) {
  const isRegister = mode === "register";
  const title = isRegister ? "Create your realm account." : "Welcome back to AzerothCore.";
  const copy = isRegister
    ? "Create one login for the website and the Wrath realm. Once inside, your account page will unlock character views, downloads, and launcher integration."
    : "Sign in to manage your AzerothCore account, review your characters, download the HD Wrath client, and keep your launcher connected to the realm.";
  const bullets = isRegister
    ? ["Website and WoW account created together", "Private access guarded by the administrator's invite question", "Client and launcher downloads unlock after login"]
    : ["Character cards, specs, gear, and account tools", "Private client and launcher downloads", "Raid loot, roster, and realm status from the portal"];
  if (isRegister && !registrationEnabled) {
    return `<section class="auth-wrap">
      <article class="auth-panel">
        <p class="eyebrow">Private Realm</p>
        <h1>Registration is closed.</h1>
        <p class="hero-copy">AzerothCore account creation is currently invite-only. Existing players can still log in to view their characters.</p>
        <p class="muted"><a href="/login">Login</a></p>
      </article>
    </section>`;
  }

  return `<section class="auth-wrap">
    <article class="auth-panel">
      <div class="auth-brand-row">
        <img src="/portal-art/portal-logo.png" alt="" aria-hidden="true">
        <div>
          <p class="eyebrow">${isRegister ? "Join AzerothCore" : "Account Portal"}</p>
          <h1>${title}</h1>
        </div>
      </div>
      <p class="hero-copy">${copy}</p>
      <div class="auth-benefits">
        ${bullets.map(item => `<span>${escapeHtml(item)}</span>`).join("")}
      </div>
      ${error ? `<div class="form-error">${escapeHtml(error)}</div>` : ""}
      <form class="auth-form" action="${isRegister ? "/register" : "/login"}" method="post">
        <label><span>Account Name</span><input name="username" value="${escapeHtml(values.username || "")}" autocomplete="username" required></label>
        ${isRegister ? `<label><span>Email</span><input name="email" type="email" value="${escapeHtml(values.email || "")}" autocomplete="email"></label>` : ""}
        <label><span>Password</span><input name="password" type="password" autocomplete="${isRegister ? "new-password" : "current-password"}" required></label>
        <button type="submit">${isRegister ? "Create Account" : "Login"}</button>
      </form>
      <p class="muted">${isRegister ? 'Already have a website account? <a href="/login">Login</a>.' : (registrationEnabled ? 'Need an account? <a href="/register">Create one</a>.' : "Registration is currently invite-only.")}</p>
    </article>
  </section>`;
}

function registrationGatePage({ status = "new", error = "" } = {}) {
  const failed = status === "failed";
  return `<section class="auth-wrap">
    <article class="auth-panel">
      <p class="eyebrow">Private Realm</p>
      <h1>${failed ? "Registration locked." : "Answer the gate question."}</h1>
      <p class="hero-copy">${failed ? "That registration attempt has already been used. Ask the administrator for help if you need an account." : "Account creation is available by invite. You get one opportunity to answer correctly."}</p>
      ${error ? `<div class="form-error">${escapeHtml(error)}</div>` : ""}
      ${failed ? `<p class="muted"><a href="/login">Login</a></p>` : `<form class="auth-form" action="/register-gate" method="post">
        <label><span>What is the invite code?</span><input name="answer" autocomplete="off" required></label>
        <button type="submit">Continue</button>
      </form>
      <p class="muted">Answer carefully. This gate only allows one try.</p>`}
    </article>
  </section>`;
}

function realmInfoParts(serverInfo) {
  const text = String(serverInfo || "");
  const uptime = text.match(/Server uptime:\s*([^]*?)\s*Update time diff:/)?.[1]?.trim() || "Checking";
  const updateDiff = text.match(/Update time diff:\s*([^.]+?)(?:\.|$)/)?.[1]?.trim() || "Unknown";
  const connected = text.match(/Connected players:\s*(\d+)/)?.[1] || "0";
  const inWorld = text.match(/Characters in world:\s*(\d+)/)?.[1] || "0";
  const peak = text.match(/Connection peak:\s*(\d+)/)?.[1] || "0";
  const build = text.match(/AzerothCore rev\.\s*([a-f0-9]+)/i)?.[1]?.slice(0, 8) || "Playerbot";

  return { uptime, updateDiff, connected, inWorld, peak, build };
}

function cpuPressure(data) {
  return Math.min(100, Math.round((data.system.load[0] / Math.max(1, data.system.cpuCount)) * 100));
}

function memoryPercent(data) {
  const memoryUsed = data.system.memoryTotal - data.system.memoryFree;
  return Math.round((memoryUsed / data.system.memoryTotal) * 100);
}

function launcherLinks() {
  const portal = process.env.PUBLIC_PORTAL_URL || "http://localhost:8088";
  return {
    portal: `${portal}/`,
    register: `${portal}/register`,
    login: `${portal}/login`,
    account: `${portal}/account`
  };
}

function portalAnnouncements() {
  return [
    {
      eyebrow: "New Admin Interface",
      title: "AI Advisor is available in the admin console.",
      body: "Ask for server checks, character lookups, inventory state, AHBot status, and approved admin actions in plain language. The advisor proposes actions, and you approve execution.",
      date: "2026-06-23",
      href: "/admin/advisor",
      cta: "Open Advisor"
    },
    {
      eyebrow: "Account Tools",
      title: "Account creation and character lookup are available.",
      body: "Use the portal registration gate to create a game account, then log in to view your characters, equipped gear, and client download links.",
      date: "2026-06-06"
    }
  ];
}

function launcherAnnouncements() {
  return portalAnnouncements().map(({ title, body, date }) => ({ title, body, date }));
}

function renderPortalAnnouncement(announcement) {
  if (!announcement) return "";
  return `<section class="advisor-announcement">
    <div>
      <span class="result-kicker">${escapeHtml(announcement.eyebrow || "Announcement")}</span>
      <h2>${escapeHtml(announcement.title)}</h2>
      <p>${escapeHtml(announcement.body)}</p>
    </div>
    ${announcement.href ? `<a class="button" href="${escapeHtml(announcement.href)}">${escapeHtml(announcement.cta || "Open")}</a>` : ""}
  </section>`;
}

function renderPortalAnnouncements() {
  const announcements = portalAnnouncements();
  if (!announcements.length) return "";
  return `<section class="portal-announcements">
    <div class="panel-head"><h2>Announcements</h2><span>Also shown in the launcher</span></div>
    <div class="portal-announcement-list">
      ${announcements.map(renderPortalAnnouncement).join("")}
    </div>
  </section>`;
}

function launcherPayload(data) {
  const realm = realmInfoParts(data.serverInfo);
  return {
    generatedAt: data.generatedAt,
    realm: {
      name: "AzerothCore",
      online: data.serverInfo !== "SOAP unavailable",
      host: process.env.REALM_HOST || "127.0.0.1",
      authPort: 3724,
      worldPort: 8085,
      client: "Wrath of the Lich King 3.3.5a",
      realmlist: `set realmlist ${process.env.REALM_HOST || "127.0.0.1"}`,
      coreRevision: realm.build
    },
    status: {
      onlineCharacters: data.counts.onlineChars,
      totalCharacters: data.counts.totalChars,
      hordeOnline: data.counts.hordeOnline,
      allianceOnline: data.counts.allianceOnline,
      auctionListings: data.counts.ahCount,
      mountAuctions: data.counts.mountAuctions,
      uptime: realm.uptime,
      updateTime: realm.updateDiff,
      connectedPlayers: Number(realm.connected),
      charactersInWorld: Number(realm.inWorld),
      connectionPeak: Number(realm.peak),
      cpuPressure: cpuPressure(data),
      memoryPercent: memoryPercent(data),
      memoryUsedGiB: Math.round((data.system.memoryTotal - data.system.memoryFree) / 1024 / 1024 / 1024),
      memoryTotalGiB: Math.round(data.system.memoryTotal / 1024 / 1024 / 1024)
    },
    links: launcherLinks(),
    announcements: launcherAnnouncements(),
    topPvp: data.topPvp.map(row => ({
      name: row.name,
      level: Number(row.level),
      race: raceNames[row.race] || `Race ${row.race}`,
      class: classNames[row.class] || `Class ${row.class}`,
      spec: row.specName || "No Spec",
      faction: factionForRace(row.race),
      honor: Number(row.totalHonorPoints),
      kills: Number(row.totalKills)
    })),
    onlineByLevel: data.onlineByLevel.map(row => ({
      bracket: row.bracket,
      count: Number(row.count)
    })),
    auctionHouseByQuality: data.ahByQuality.map(row => ({
      quality: Number(row.quality),
      qualityName: qualityNames[row.quality] || `Quality ${row.quality}`,
      count: Number(row.count)
    }))
  };
}

function launcherAccountPayload(row, characterCount = 0) {
  return {
    accountId: Number(row.account_id),
    username: String(row.username || "").toUpperCase(),
    lastLogin: row.last_login ? new Date(row.last_login).toISOString() : null,
    characterCount: Number(characterCount || 0)
  };
}

function launcherCharacterPayload(row, gearSummary = {}, specName = "") {
  return {
    guid: Number(row.guid),
    name: row.name,
    level: Number(row.level),
    race: raceNames[row.race] || `Race ${row.race}`,
    class: classNames[row.class] || `Class ${row.class}`,
    spec: specName || "No Spec",
    gender: genderNames[row.gender] || `Gender ${row.gender}`,
    faction: factionForRace(row.race),
    online: Boolean(Number(row.online)),
    zone: zoneLabel(row.zone, row.zoneName),
    map: mapLabel(row.map),
    money: Number(row.money || 0),
    totalKills: Number(row.totalKills || 0),
    totalHonorPoints: Number(row.totalHonorPoints || 0),
    gearScore: Number(gearSummary.gearScore || 0),
    averageItemLevel: Number(gearSummary.averageItemLevel || 0)
  };
}

function isoDateOrNull(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function launcherRaidRosterPayload(rows) {
  return {
    generatedAt: new Date().toISOString(),
    characters: rows.map(row => ({
      guid: Number(row.guid),
      name: row.name,
      account: String(row.username || "").toUpperCase(),
      level: Number(row.level),
      race: raceNames[row.race] || `Race ${row.race}`,
      class: classNames[row.class] || `Class ${row.class}`,
      spec: row.specName || "No Spec",
      role: row.role || roleForSpec(Number(row.class), row.specName || ""),
      faction: factionForRace(row.race),
      online: Boolean(Number(row.online)),
      zone: zoneLabel(row.zone, row.zoneName),
      map: mapLabel(row.map),
      totalKills: Number(row.totalKills || 0),
      totalHonorPoints: Number(row.totalHonorPoints || 0),
      gearScore: 0,
      averageItemLevel: Number(row.averageItemLevel || 0),
      equippedCombatSlots: Number(row.equippedCombatSlots || 0)
    }))
  };
}

function launcherRealmPopulationPayload(realmData) {
  const summary = realmData.summary || {};
  const horde = keyedCount(realmData.factionRows, "faction", "Horde");
  const alliance = keyedCount(realmData.factionRows, "faction", "Alliance");
  const location = name => Number(realmData.locationRows.find(row => row.bucket === name)?.count || 0);
  const totalOnlineTracked = realmData.accountRows.reduce((sum, row) => sum + Number(row.count || 0), 0);

  return {
    generatedAt: new Date().toISOString(),
    summary: {
      totalCharacters: Number(summary.totalCharacters || 0),
      onlineNow: Number(summary.onlineNow || 0),
      guilds: Number(summary.guildCount || 0),
      averageLevel: Number(summary.avgLevel || 0),
      level80: Number(summary.level80 || 0),
      economyGold: Math.round(Number(summary.totalCopper || 0) / 10000)
    },
    factions: {
      alliance,
      horde
    },
    locations: {
      world: location("Out in the world"),
      cities: location("Cities"),
      dungeons: location("Dungeons"),
      raids: location("Raids"),
      battlegrounds: location("Battlegrounds"),
      worldRandom: keyedCount(realmData.accountRows, "bucket", "World/random"),
      gmAccounts: keyedCount(realmData.accountRows, "bucket", "GM accounts"),
      totalOnlineTracked
    },
    topZones: realmData.topZones.map(row => ({
      mapId: Number(row.map),
      map: mapLabel(row.map),
      zoneId: Number(row.zone),
      zone: zoneLabel(row.zone, row.zoneName),
      count: Number(row.count || 0)
    })),
    levelBrackets: realmData.levelRows.map(row => ({
      bracket: row.bracket,
      count: Number(row.count || 0)
    })),
    classes: realmData.classRows.map(row => ({
      classId: Number(row.class),
      class: classNames[row.class] || `Class ${row.class}`,
      count: Number(row.count || 0)
    })),
    races: realmData.raceRows.map(row => ({
      raceId: Number(row.race),
      race: raceNames[row.race] || `Race ${row.race}`,
      faction: factionForRace(row.race),
      count: Number(row.count || 0)
    }))
  };
}

function launcherServerRaidLootPayload(result) {
  const dateOnly = value => {
    const iso = isoDateOrNull(value);
    return iso ? iso.slice(0, 10) : null;
  };
  return {
    generatedAt: new Date().toISOString(),
    installed: Boolean(result.installed),
    runs: (result.runs || []).map(row => ({
      runKey: row.serverRunKey || row.runKey,
      sourceRunKey: row.sourceRunKey || row.runKey,
      lootDate: dateOnly(row.lootDate),
      instanceName: mapLabel(row.mapId),
      mapId: Number(row.mapId || 0),
      instanceId: Number(row.instanceId || 0),
      startedAt: isoDateOrNull(row.startedAt),
      endedAt: isoDateOrNull(row.endedAt),
      lastDropAt: isoDateOrNull(row.endedAt),
      dropCount: Number(row.dropCount || 0),
      rareCount: Number(row.rareCount || 0),
      epicCount: Number(row.epicCount || 0),
      legendaryCount: Number(row.legendaryCount || 0),
      looterCount: Number(row.looterCount || 0)
    }))
  };
}

async function getLauncherGearSummaries(guids) {
  const uniqueGuids = [...new Set(guids.map(Number).filter(Number.isFinite))];
  if (!uniqueGuids.length) return new Map();

  const placeholders = uniqueGuids.map(() => "?").join(",");
  const [rows] = await db.query(`SELECT
      ci.guid,
      ci.slot,
      it.ItemLevel itemLevel
    FROM acore_characters.character_inventory ci
    JOIN acore_characters.item_instance ii ON ii.guid = ci.item
    JOIN acore_world.item_template it ON it.entry = ii.itemEntry
    WHERE ci.bag = 0
      AND ci.slot IN (${[...combatGearSlots].map(() => "?").join(",")})
      AND ci.guid IN (${placeholders})`, [...combatGearSlots, ...uniqueGuids]);

  const totals = new Map();
  for (const row of rows) {
    const guid = Number(row.guid);
    const itemLevel = Number(row.itemLevel || 0);
    if (!combatGearSlots.has(Number(row.slot)) || itemLevel <= 0) continue;
    if (!totals.has(guid)) totals.set(guid, { totalItemLevel: 0, count: 0 });
    const summary = totals.get(guid);
    summary.totalItemLevel += itemLevel;
    summary.count += 1;
  }

  const summaries = new Map();
  for (const guid of uniqueGuids) {
    const summary = totals.get(guid);
    summaries.set(guid, {
      gearScore: 0,
      averageItemLevel: summary?.count ? Math.round(summary.totalItemLevel / summary.count) : 0
    });
  }
  return summaries;
}

async function getLauncherCharacters(accountId, guid = null) {
  const params = { accountId };
  const guidSql = guid === null ? "" : "AND c.guid = :guid";
  if (guid !== null) params.guid = guid;
  return await query(`SELECT
      c.guid, c.name, c.level, c.race, c.class, c.gender, c.zone, c.map, c.money,
      c.online, c.activeTalentGroup, c.totalKills, c.totalHonorPoints,
      COALESCE(NULLIF(area.AreaName_Lang_enUS, ''), NULL) zoneName
    FROM acore_characters.characters c
    LEFT JOIN acore_world.areatable_dbc area ON area.ID = c.zone
    WHERE c.account = :accountId
      ${guidSql}
    ORDER BY c.level DESC, c.name`, params);
}

function cleanShortText(value, maxLength, fallback = "") {
  const text = String(value || "").trim().replace(/\s+/g, " ").slice(0, maxLength);
  return text || fallback;
}

function cleanNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? Math.floor(number) : fallback;
}

function normalizeLootRunPayload(body, accountId) {
  const run = body?.run && typeof body.run === "object" ? body.run : {};
  const sourceRunId = cleanShortText(run.sourceRunId || body?.sourceRunId, 96);
  if (!sourceRunId) throw new Error("run.sourceRunId is required.");

  const instanceName = cleanShortText(run.instanceName, 96, "Unknown Instance");
  const bossKills = Array.isArray(body?.bossKills) ? body.bossKills.slice(0, 80) : [];
  const drops = Array.isArray(body?.drops) ? body.drops.slice(0, 250) : [];
  if (!drops.length && !bossKills.length) throw new Error("Upload must include at least one boss kill or loot drop.");

  return {
    run: {
      sourceRunId,
      uploaderAccountId: Number(accountId),
      instanceName,
      mapId: cleanNumber(run.mapId),
      difficulty: cleanShortText(run.difficulty, 32),
      startedAt: mysqlOptionalDate(run.startedAt),
      endedAt: mysqlOptionalDate(run.endedAt),
      note: cleanShortText(run.note, 255)
    },
    bossKills: bossKills.map((boss, index) => {
      const sourceBossId = cleanShortText(boss.sourceBossId || `${sourceRunId}:boss:${index + 1}`, 96);
      return {
        sourceBossId,
        bossName: cleanShortText(boss.bossName, 96, "Unknown Boss"),
        bossEntry: cleanNumber(boss.bossEntry),
        encounterId: cleanNumber(boss.encounterId),
        killedAt: mysqlOptionalDate(boss.killedAt)
      };
    }),
    drops: drops
      .map((drop, index) => {
        const quality = cleanNumber(drop.quality);
        return {
          eventId: cleanShortText(drop.eventId || `${sourceRunId}:drop:${index + 1}`, 128),
          sourceBossId: cleanShortText(drop.sourceBossId || drop.bossSourceId, 96),
          recipientGuid: cleanNumber(drop.recipientGuid) || null,
          recipientName: cleanShortText(drop.recipientName, 32, "Unknown"),
          itemEntry: cleanNumber(drop.itemEntry),
          itemName: cleanShortText(drop.itemName, 128, "Unknown Item"),
          itemLink: String(drop.itemLink || "").trim().slice(0, 2048),
          quality,
          quantity: Math.max(1, cleanNumber(drop.quantity, 1)),
          lootedAt: mysqlOptionalDate(drop.lootedAt),
          rawJson: JSON.stringify(drop).slice(0, 8192)
        };
      })
      .filter(drop => trackedLootQualities.has(drop.quality) && drop.itemEntry > 0)
  };
}

async function saveRaidLootUpload(payload) {
  await ensurePortalTables();
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    await connection.query(`INSERT INTO acore_auth.portal_raid_runs
        (source_run_id, uploader_account_id, instance_name, map_id, difficulty, started_at, ended_at, note)
      VALUES (:sourceRunId, :uploaderAccountId, :instanceName, :mapId, :difficulty, :startedAt, :endedAt, :note)
      ON DUPLICATE KEY UPDATE
        instance_name = VALUES(instance_name),
        map_id = VALUES(map_id),
        difficulty = VALUES(difficulty),
        started_at = COALESCE(VALUES(started_at), started_at),
        ended_at = COALESCE(VALUES(ended_at), ended_at),
        note = VALUES(note),
        updated_at = CURRENT_TIMESTAMP`, payload.run);

    const [runRows] = await connection.query("SELECT id FROM acore_auth.portal_raid_runs WHERE source_run_id = :sourceRunId LIMIT 1", { sourceRunId: payload.run.sourceRunId });
    const runId = Number(runRows[0]?.id);
    if (!runId) throw new Error("Could not create or load raid run.");

    const bossIdsBySource = new Map();
    for (const boss of payload.bossKills) {
      await connection.query(`INSERT INTO acore_auth.portal_raid_boss_kills
          (run_id, source_boss_id, boss_name, boss_entry, encounter_id, killed_at)
        VALUES (:runId, :sourceBossId, :bossName, :bossEntry, :encounterId, :killedAt)
        ON DUPLICATE KEY UPDATE
          boss_name = VALUES(boss_name),
          boss_entry = VALUES(boss_entry),
          encounter_id = VALUES(encounter_id),
          killed_at = COALESCE(VALUES(killed_at), killed_at)`, { runId, ...boss });
    }

    const [bossRows] = await connection.query("SELECT id, source_boss_id FROM acore_auth.portal_raid_boss_kills WHERE run_id = :runId", { runId });
    for (const row of bossRows) bossIdsBySource.set(String(row.source_boss_id), Number(row.id));

    let storedDrops = 0;
    for (const drop of payload.drops) {
      const bossId = drop.sourceBossId ? bossIdsBySource.get(drop.sourceBossId) || null : null;
      const [result] = await connection.query(`INSERT IGNORE INTO acore_auth.portal_raid_loot_drops
          (run_id, boss_id, event_id, uploader_account_id, recipient_guid, recipient_name, item_entry, item_name, item_link, quality, quantity, looted_at, raw_json)
        VALUES (:runId, :bossId, :eventId, :uploaderAccountId, :recipientGuid, :recipientName, :itemEntry, :itemName, :itemLink, :quality, :quantity, :lootedAt, :rawJson)`, {
        runId,
        bossId,
        uploaderAccountId: payload.run.uploaderAccountId,
        ...drop
      });
      storedDrops += Number(result.affectedRows || 0);
    }

    await connection.commit();
    return { runId, bossKills: payload.bossKills.length, acceptedDrops: payload.drops.length, storedDrops };
  } catch (error) {
    try {
      await connection.rollback();
    } catch (rollbackError) {
      console.error("Raid loot upload rollback failed:", rollbackError);
    }
    throw error;
  } finally {
    connection.release();
  }
}

async function getRaidLootRuns(limit = 20) {
  await ensurePortalTables();
  return await query(`SELECT
      r.id,
      r.source_run_id sourceRunId,
      r.instance_name instanceName,
      r.map_id mapId,
      r.difficulty,
      r.started_at startedAt,
      r.ended_at endedAt,
      r.note,
      pu.username uploadedBy,
      COUNT(DISTINCT b.id) bossCount,
      COUNT(d.id) dropCount,
      SUM(d.quality = 3) rareCount,
      SUM(d.quality = 4) epicCount,
      SUM(d.quality = 5) legendaryCount
    FROM acore_auth.portal_raid_runs r
    LEFT JOIN acore_auth.portal_users pu ON pu.account_id = r.uploader_account_id
    LEFT JOIN acore_auth.portal_raid_boss_kills b ON b.run_id = r.id
    LEFT JOIN acore_auth.portal_raid_loot_drops d ON d.run_id = r.id
    GROUP BY r.id
    ORDER BY COALESCE(r.started_at, r.created_at) DESC, r.id DESC
    LIMIT :limit`, { limit });
}

async function getRaidLootRunDetail(runId) {
  await ensurePortalTables();
  const runs = await query(`SELECT
      r.id,
      r.source_run_id sourceRunId,
      r.instance_name instanceName,
      r.map_id mapId,
      r.difficulty,
      r.started_at startedAt,
      r.ended_at endedAt,
      r.note,
      pu.username uploadedBy
    FROM acore_auth.portal_raid_runs r
    LEFT JOIN acore_auth.portal_users pu ON pu.account_id = r.uploader_account_id
    WHERE r.id = :runId
    LIMIT 1`, { runId });
  if (!runs.length) return null;

  const bosses = await query(`SELECT id, source_boss_id sourceBossId, boss_name bossName, boss_entry bossEntry, encounter_id encounterId, killed_at killedAt
    FROM acore_auth.portal_raid_boss_kills
    WHERE run_id = :runId
    ORDER BY COALESCE(killed_at, created_at), id`, { runId });

  const drops = await query(`SELECT
      d.id,
      d.boss_id bossId,
      d.event_id eventId,
      d.recipient_guid recipientGuid,
      d.recipient_name recipientName,
      COALESCE(cg.class, cn.class) recipientClass,
      d.item_entry itemEntry,
      d.item_name itemName,
      d.item_link itemLink,
      d.quality,
      d.quantity,
      d.looted_at lootedAt
    FROM acore_auth.portal_raid_loot_drops d
    LEFT JOIN acore_characters.characters cg ON cg.guid = d.recipient_guid
    LEFT JOIN acore_characters.characters cn ON cn.name = d.recipient_name
    WHERE d.run_id = :runId
    ORDER BY COALESCE(d.looted_at, d.created_at), d.id`, { runId });

  return { run: runs[0], bosses, drops };
}

async function serverLootTableInstalled() {
  const rows = await query("SHOW TABLES FROM acore_characters LIKE 'acore_portal_raid_loot_events'");
  return rows.length > 0;
}

async function worldBossKillTableInstalled() {
  const rows = await query("SHOW TABLES FROM acore_characters LIKE 'acore_portal_world_boss_kills'");
  return rows.length > 0;
}

async function getServerRaidLootRuns(limit = 20) {
  if (!(await serverLootTableInstalled())) return { installed: false, runs: [] };

  const runs = await query(`SELECT
      CONCAT(e.run_key, '_', DATE(MIN(e.looted_at))) serverRunKey,
      e.run_key sourceRunKey,
      e.run_key runKey,
      DATE(MIN(e.looted_at)) lootDate,
      e.map_id mapId,
      e.instance_id instanceId,
      MIN(e.looted_at) startedAt,
      MAX(e.looted_at) endedAt,
      COUNT(*) dropCount,
      SUM(e.item_quality = 3) rareCount,
      SUM(e.item_quality = 4) epicCount,
      SUM(e.item_quality >= 5) legendaryCount,
      COUNT(DISTINCT e.looter_guid) looterCount
    FROM acore_characters.acore_portal_raid_loot_events e
    GROUP BY e.run_key, DATE(e.looted_at), e.map_id, e.instance_id
    ORDER BY MAX(e.looted_at) DESC, MAX(e.id) DESC
    LIMIT :limit`, { limit });

  if (await worldBossKillTableInstalled()) {
    const killRuns = await query(`SELECT
        CONCAT(k.run_key, '_', DATE(MIN(k.killed_at))) serverRunKey,
        k.run_key sourceRunKey,
        k.run_key runKey,
        DATE(MIN(k.killed_at)) lootDate,
        k.map_id mapId,
        0 instanceId,
        MIN(k.killed_at) startedAt,
        MAX(k.killed_at) endedAt,
        0 dropCount,
        0 rareCount,
        0 epicCount,
        0 legendaryCount,
        0 looterCount
      FROM acore_characters.acore_portal_world_boss_kills k
      GROUP BY k.run_key, DATE(k.killed_at), k.map_id
      ORDER BY MAX(k.killed_at) DESC, MAX(k.id) DESC
      LIMIT :limit`, { limit });

    const byRun = new Map(runs.map(run => [run.serverRunKey || run.runKey, run]));
    for (const run of killRuns) {
      if (!byRun.has(run.serverRunKey || run.runKey)) {
        runs.push(run);
      }
    }

    runs.sort((a, b) => new Date(b.endedAt || b.startedAt || 0) - new Date(a.endedAt || a.startedAt || 0));
    runs.splice(limit);
  }

  return { installed: true, runs };
}

async function getServerRaidLootRunDetail(runKey) {
  const match = String(runKey || "").match(/^([a-z0-9-]+|\d+-\d+)(?:_(\d{4}-\d{2}-\d{2}))?$/i);
  if (!match) throw new Error("Server run key must be map-instance or worldboss-entry, optionally followed by _YYYY-MM-DD.");
  if (!(await serverLootTableInstalled())) return null;
  const sourceRunKey = match[1];
  const lootDate = match[2] || "";
  const dateFilter = lootDate ? "AND DATE(e.looted_at) = :lootDate" : "";
  const params = { sourceRunKey, lootDate };

  const runs = await query(`SELECT
      ${lootDate ? "CONCAT(e.run_key, '_', DATE(MIN(e.looted_at)))" : "e.run_key"} serverRunKey,
      e.run_key sourceRunKey,
      e.run_key runKey,
      DATE(MIN(e.looted_at)) lootDate,
      e.map_id mapId,
      e.instance_id instanceId,
      MIN(e.looted_at) startedAt,
      MAX(e.looted_at) endedAt,
      COUNT(*) dropCount,
      COUNT(DISTINCT e.looter_guid) looterCount
    FROM acore_characters.acore_portal_raid_loot_events e
    WHERE e.run_key = :sourceRunKey
      ${dateFilter}
    GROUP BY e.run_key, DATE(e.looted_at), e.map_id, e.instance_id
    ORDER BY MAX(e.looted_at) DESC, MAX(e.id) DESC
    LIMIT 1`, params);

  let worldBossKills = [];
  const isWorldBossRun = /^worldboss-\d+$/i.test(sourceRunKey);
  if (isWorldBossRun && await worldBossKillTableInstalled()) {
    const killDateFilter = lootDate ? "AND DATE(k.killed_at) = :lootDate" : "";
    worldBossKills = await query(`SELECT
        k.id,
        k.boss_entry bossEntry,
        k.boss_name bossName,
        k.creature_guid creatureGuid,
        k.killer_guid killerGuid,
        k.killer_name killerName,
        COALESCE(cg.class, cn.class) killerClass,
        k.map_id mapId,
        k.position_x positionX,
        k.position_y positionY,
        k.position_z positionZ,
        k.run_key runKey,
        k.killed_at killedAt
      FROM acore_characters.acore_portal_world_boss_kills k
      LEFT JOIN acore_characters.characters cg ON cg.guid = k.killer_guid
      LEFT JOIN acore_characters.characters cn ON cn.name = k.killer_name
      WHERE k.run_key = :sourceRunKey
        ${killDateFilter}
      ORDER BY k.killed_at DESC, k.id DESC`, params);
  }

  if (!runs.length && worldBossKills.length) {
    const kill = worldBossKills[0];
    runs.push({
      serverRunKey: lootDate ? `${sourceRunKey}_${lootDate}` : sourceRunKey,
      sourceRunKey,
      runKey: sourceRunKey,
      lootDate: lootDate || String(kill.killedAt || "").slice(0, 10),
      mapId: kill.mapId,
      instanceId: 0,
      startedAt: kill.killedAt,
      endedAt: kill.killedAt,
      dropCount: 0,
      looterCount: 0
    });
  }

  if (!runs.length) return null;

  const drops = await query(`SELECT
      e.id,
      e.looted_at lootedAt,
      e.map_id mapId,
      e.instance_id instanceId,
      e.encounter_mask encounterMask,
      e.looter_guid recipientGuid,
      e.looter_name recipientName,
      COALESCE(cg.class, cn.class) recipientClass,
      e.item_entry itemEntry,
      COALESCE(NULLIF(it.name, ''), CONCAT('Item ', e.item_entry)) itemName,
      e.item_count quantity,
      e.item_quality quality,
      e.item_level itemLevel,
      e.loot_source_guid lootSourceGuid
    FROM acore_characters.acore_portal_raid_loot_events e
    LEFT JOIN acore_characters.characters cg ON cg.guid = e.looter_guid
    LEFT JOIN acore_characters.characters cn ON cn.name = e.looter_name
    LEFT JOIN acore_world.item_template it ON it.entry = e.item_entry
    WHERE e.run_key = :sourceRunKey
      ${dateFilter}
    ORDER BY e.looted_at, e.id`, params);

  return { run: runs[0], drops, worldBossKills };
}

async function requireLauncherAuth(req, res, next) {
  try {
    await ensurePortalTables();
    const authHeader = String(req.headers.authorization || "");
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (!match) return jsonError(res, 401, "Missing bearer token.");

    const hash = tokenHash(match[1].trim());
    const rows = await query(`SELECT
        t.id tokenId,
        t.account_id,
        pu.username,
        pu.last_login
      FROM acore_auth.portal_launcher_tokens t
      JOIN acore_auth.portal_users pu ON pu.account_id = t.account_id
      WHERE t.token_hash = :hash
        AND t.revoked_at IS NULL
        AND t.expires_at > UTC_TIMESTAMP()
      LIMIT 1`, { hash });

    if (!rows.length) return jsonError(res, 401, "Invalid or expired launcher token.");

    await query("UPDATE acore_auth.portal_launcher_tokens SET last_used_at = UTC_TIMESTAMP() WHERE id = :id", { id: rows[0].tokenId });
    req.launcherUser = rows[0];
    next();
  } catch (error) {
    return jsonError(res, 500, error.message || "Launcher authentication failed.");
  }
}

function renderDashboard(data, admin = false) {
  const memoryUsed = data.system.memoryTotal - data.system.memoryFree;
  const memoryPct = memoryPercent(data);
  const cpuLoad = cpuPressure(data);
  const uptimeHours = Math.floor(data.system.uptime / 3600);
  const realm = realmInfoParts(data.serverInfo);
  const realmOnline = data.serverInfo !== "SOAP unavailable";
  const realmStatus = realmOnline ? "Online" : "Offline";
  const realmStatusImage = realmOnline ? "/portal-art/realm-online.png" : "/portal-art/realm-offline.png";
  const realmStatusMessage = realmOnline ? "Worldserver responding" : "Worldserver unavailable";

  return `
  <section class="hero">
    <div>
      <p class="eyebrow">Private AzerothCore Realm</p>
      <h1>AzerothCore</h1>
      <p class="hero-copy">Manage accounts, characters, playerbots, auctions, and server status for the AzerothCore realm.</p>
    </div>
    <div class="realm-card ${realmOnline ? "is-online" : "is-offline"}">
      <div class="realm-card-head">
        <img class="realm-status-mini" src="${realmStatusImage}" alt="" aria-hidden="true">
        <div class="realm-caption">
          <b></b>
          <span>Realm status</span>
          <strong>${realmStatus}</strong>
          <small>${realmStatusMessage}</small>
        </div>
      </div>
      <dl class="realm-metrics">
        <div><dt>Uptime</dt><dd>${escapeHtml(realm.uptime)}</dd></div>
        <div><dt>Tick</dt><dd>${escapeHtml(realm.updateDiff)}</dd></div>
        <div><dt>Players</dt><dd>${Number(realm.connected).toLocaleString()}</dd></div>
        <div><dt>World</dt><dd>${Number(realm.inWorld).toLocaleString()}</dd></div>
      </dl>
      <div class="realm-build">
        <span>Core ${escapeHtml(realm.build)}</span>
        <span>Peak ${Number(realm.peak).toLocaleString()}</span>
      </div>
    </div>
  </section>

  <section class="stats-grid">
    ${statCard("Online", data.counts.onlineChars.toLocaleString(), "characters and bots")}
    ${statCard("Horde", data.counts.hordeOnline.toLocaleString(), "online now")}
    ${statCard("Alliance", data.counts.allianceOnline.toLocaleString(), "online now")}
    ${statCard("Auction House", data.counts.ahCount.toLocaleString(), "active listings")}
    ${statCard("CPU Pressure", `${cpuLoad}%`, `${data.system.cpuCount} threads available`)}
    ${statCard("Memory", `${memoryPct}%`, `${Math.round(memoryUsed / 1024 / 1024 / 1024)} / ${Math.round(data.system.memoryTotal / 1024 / 1024 / 1024)} GiB`)}
  </section>

  ${!admin ? `<section class="panel-grid">
    <article class="panel">
      <div class="panel-head"><h2>Top PvP</h2><span>Honor, then kills</span></div>
      <table>
        <thead><tr><th>Name</th><th>Spec</th><th>Level</th><th>Honor</th><th>Kills</th></tr></thead>
        <tbody>
          ${data.topPvp.map(row => `<tr><td><span class="name-with-icon">${classBadge(row.class)}${escapeHtml(row.name)}</span></td><td>${escapeHtml(row.specName || "No Spec")}</td><td>${row.level}</td><td>${Number(row.totalHonorPoints).toLocaleString()}</td><td>${Number(row.totalKills).toLocaleString()}</td></tr>`).join("")}
        </tbody>
      </table>
    </article>
    <article class="panel">
      <div class="panel-head"><h2>Online Levels</h2><span>Current world shape</span></div>
      <div class="bars">
        ${data.onlineByLevel.map(row => {
          const pct = Math.min(100, Math.round((Number(row.count) / Math.max(1, data.counts.onlineChars)) * 100));
          return `<div class="bar-row"><span>${escapeHtml(row.bracket)}</span><div><i style="width:${pct}%"></i></div><strong>${row.count}</strong></div>`;
        }).join("")}
      </div>
    </article>
  </section>` : ""}

  ${renderPortalAnnouncements()}

  ${admin ? `
  ${renderAdminHub()}
  <section class="panel-grid">
    <article class="panel">
      <div class="panel-head"><h2>World Pulse</h2><span>Deeper population data lives on the realm page</span></div>
      <div class="health-check-list">
        <div><strong>Online</strong><span>${data.counts.onlineChars.toLocaleString()} characters and bots</span></div>
        <div><strong>Faction Split</strong><span>${data.counts.hordeOnline.toLocaleString()} Horde / ${data.counts.allianceOnline.toLocaleString()} Alliance</span></div>
        <div><strong>Auction House</strong><span>${data.counts.ahCount.toLocaleString()} active listings</span></div>
        <div><strong>Realm</strong><span>${realmOnline ? "Worldserver responding" : "Worldserver unavailable"}</span></div>
      </div>
      <a class="button" href="/admin/realm">Open Realm & Population</a>
    </article>
    <article class="panel">
      <div class="panel-head"><h2>Character Lookup</h2><span>Fast admin search</span></div>
      <form class="lookup" action="/admin/character" method="get">
        <input name="q" placeholder="Charactername, Healername, Tankname..." required>
        <button type="submit">Search</button>
      </form>
      <p class="muted">Search first when you want to confirm map, level, title, class, and account before running a character action.</p>
      <p class="muted">Portal uptime: ${uptimeHours.toLocaleString()} hours.</p>
    </article>
    ${renderAdminActionHistory(data.adminHistory || [])}
  </section>
  ` : ""}
  `;
}

function renderTalentCalculator() {
  const wowheadBaseUrl = "https://www.wowhead.com/wotlk/talent-calc";
  const tabs = [
    { label: "Death Knight", slug: "death-knight", title: "Death Knight Talents" },
    { label: "Druid", slug: "druid", title: "Druid Talents" },
    { label: "Hunter", slug: "hunter", title: "Hunter Talents" },
    { label: "Mage", slug: "mage", title: "Mage Talents" },
    { label: "Paladin", slug: "paladin", title: "Paladin Talents" },
    { label: "Priest", slug: "priest", title: "Priest Talents" },
    { label: "Rogue", slug: "rogue", title: "Rogue Talents" },
    { label: "Shaman", slug: "shaman", title: "Shaman Talents" },
    { label: "Warlock", slug: "warlock", title: "Warlock Talents" },
    { label: "Warrior", slug: "warrior", title: "Warrior Talents" }
  ];
  const embedUrl = slug => `${wowheadBaseUrl}/embed${slug ? `/${slug}` : ""}`;

  return `
  <section class="page-head talent-head">
    <div>
      <p class="eyebrow">Wrath 3.3.5</p>
      <h1>Talent Calculator</h1>
      <p class="hero-copy">Use Wowhead's embedded Wrath of the Lich King calculator, with quick tabs for every class.</p>
    </div>
  </section>
  <article class="panel talent-panel">
    <div class="talent-frame-head">
      <div>
        <h2>Wowhead WotLK Talent Calculator</h2>
        <span>Standard class trees, talents, and glyph planning</span>
      </div>
      <div class="talent-actions">
        <a class="button" id="talent-open-link" href="${wowheadBaseUrl}/${tabs[0].slug}" target="_blank" rel="noreferrer">Open Fullscreen</a>
      </div>
    </div>
    <div class="talent-tabs" role="tablist" aria-label="Wrath talent calculator classes">
      ${tabs.map((tab, index) => `<button
        type="button"
        class="talent-tab${index === 0 ? " active" : ""}"
        data-src="${escapeHtml(embedUrl(tab.slug))}"
        data-open="${escapeHtml(tab.slug ? `${wowheadBaseUrl}/${tab.slug}` : wowheadBaseUrl)}"
        data-title="${escapeHtml(tab.title)}"
        role="tab"
        aria-selected="${index === 0 ? "true" : "false"}"
      >${escapeHtml(tab.label)}</button>`).join("")}
    </div>
    <div class="talent-embed-shell">
      <iframe
        id="talent-frame"
        class="talent-embed"
        src="${embedUrl(tabs[0].slug)}"
        title="${escapeHtml(tabs[0].title)}"
        loading="lazy"
        referrerpolicy="no-referrer"
      ></iframe>
    </div>
    <p class="muted talent-note">These use Wowhead's WotLK embed pages, so they load inside the portal instead of being blocked by the normal Wowhead frame policy.</p>
    <script>
      document.querySelectorAll(".talent-tab").forEach(tab => {
        tab.addEventListener("click", () => {
          const frame = document.getElementById("talent-frame");
          const openLink = document.getElementById("talent-open-link");
          document.querySelectorAll(".talent-tab").forEach(item => {
            item.classList.toggle("active", item === tab);
            item.setAttribute("aria-selected", item === tab ? "true" : "false");
          });
          frame.src = tab.dataset.src;
          frame.title = tab.dataset.title;
          openLink.href = tab.dataset.open;
        });
      });
    </script>
  </article>`;
}

app.get("/", async (_req, res) => {
  try {
    const data = await getPortalData();
    res.send(layout({ title: "AzerothCore", body: renderDashboard(data), user: currentUser(_req) }));
  } catch (error) {
    res.status(500).send(layout({ title: "AzerothCore", body: `<section class="panel error"><h1>Portal error</h1><pre>${escapeHtml(error.stack || error.message)}</pre></section>` }));
  }
});

app.get("/talents", (req, res) => {
  res.send(layout({ title: "Talent Calculator", body: renderTalentCalculator(), user: currentUser(req) }));
});

app.get("/register", (_req, res) => {
  if (!registrationEnabled) {
    return res.send(layout({ title: "Create Account", body: authPage({ mode: "register" }), user: currentUser(_req) }));
  }

  const gateStatus = registrationGateStatus(_req);
  if (gateStatus !== "passed") {
    return res.send(layout({
      title: "Registration Gate",
      body: registrationGatePage({ status: gateStatus }),
      user: currentUser(_req)
    }));
  }

  res.send(layout({ title: "Create Account", body: authPage({ mode: "register" }), user: currentUser(_req) }));
});

app.post("/register-gate", (req, res) => {
  if (!registrationEnabled) return res.redirect("/register");
  if (registrationGateStatus(req) === "failed") {
    return res.status(403).send(layout({
      title: "Registration Locked",
      body: registrationGatePage({ status: "failed" }),
      user: currentUser(req)
    }));
  }

  const answer = String(req.body.answer || "").trim().toLowerCase();
  if (answer === registrationAnswer) {
    setRegistrationGate(res, req, "passed");
    return res.redirect("/register");
  }

  setRegistrationGate(res, req, "failed");
  return res.status(403).send(layout({
    title: "Registration Locked",
    body: registrationGatePage({ status: "failed", error: "That answer was not accepted." }),
    user: currentUser(req)
  }));
});

app.post("/register", async (req, res) => {
  const values = { username: req.body.username || "", email: req.body.email || "" };

  try {
    if (!registrationEnabled) throw new Error("Registration is currently closed.");
    if (registrationGateStatus(req) !== "passed") throw new Error("Answer the registration question before creating an account.");
    await ensurePortalTables();
    const username = cleanAccountName(req.body.username);
    const password = cleanAccountPassword(req.body.password);
    const email = cleanEmail(req.body.email);

    const existing = await query("SELECT id FROM acore_auth.account WHERE username = :username LIMIT 1", { username });
    if (existing.length) throw new Error("That account name already exists.");

    await soapCommand(`account create ${username} ${password}`);
    if (email) await query("UPDATE acore_auth.account SET email = :email, reg_mail = :email WHERE username = :username", { email, username });

    const accounts = await query("SELECT id, username FROM acore_auth.account WHERE username = :username LIMIT 1", { username });
    if (!accounts.length) throw new Error("Account was created, but the portal could not link it yet.");

    const { salt, hash } = passwordHash(password);
    await query(`INSERT INTO acore_auth.portal_users (account_id, username, email, password_salt, password_hash)
      VALUES (:accountId, :username, :email, :salt, :hash)`, {
      accountId: accounts[0].id,
      username,
      email,
      salt,
      hash
    });

    setSession(req, res, { id: accounts[0].id, username, isAdmin: false });
    res.redirect("/account?created=1");
  } catch (error) {
    res.status(400).send(layout({
      title: "Create Account",
      body: authPage({ mode: "register", error: error.message, values }),
      user: currentUser(req)
    }));
  }
});

app.get("/login", (_req, res) => {
  res.send(layout({ title: "Login", body: authPage({ mode: "login" }), user: currentUser(_req) }));
});

app.post("/login", async (req, res) => {
  const values = { username: req.body.username || "" };

  try {
    await ensurePortalTables();
    const username = cleanAccountName(req.body.username);
    const password = String(req.body.password || "");
    const rows = await query("SELECT account_id, username, password_salt, password_hash, is_admin isAdmin FROM acore_auth.portal_users WHERE username = :username LIMIT 1", { username });
    if (!rows.length || !verifyPassword(password, rows[0].password_salt, rows[0].password_hash)) {
      throw new Error("Account name or password did not match.");
    }

    await query("UPDATE acore_auth.portal_users SET last_login = CURRENT_TIMESTAMP WHERE account_id = :accountId", { accountId: rows[0].account_id });
    setSession(req, res, { id: rows[0].account_id, username: rows[0].username, isAdmin: Boolean(rows[0].isAdmin) });
    res.redirect("/account");
  } catch (error) {
    res.status(401).send(layout({
      title: "Login",
      body: authPage({ mode: "login", error: error.message, values }),
      user: currentUser(req)
    }));
  }
});

app.post("/logout", (req, res) => {
  clearSession(req, res);
  res.redirect("/");
});

app.get("/account", requireUser, async (req, res) => {
  await ensurePortalTables();
  const accountCreated = String(req.query.created || "") === "1";
  const rows = await query(`SELECT c.guid, c.name, c.level, c.race, c.class, c.online, c.map, c.activeTalentGroup,
      c.position_x, c.position_y, c.position_z, c.totalHonorPoints, c.totalKills,
      c.chosenTitle, a.username
    FROM acore_characters.characters c
    JOIN acore_auth.account a ON a.id = c.account
    WHERE c.account = :accountId
    ORDER BY c.level DESC, c.name`, { accountId: req.portalUser.id });
  const guids = rows.map(row => Number(row.guid));
  const [gearByGuid, specsByGuid] = await Promise.all([
    getEquippedGear(guids),
    getCharacterSpecs(rows)
  ]);

  const body = `
    <section class="page-head account-head account-characters-head">
      <div class="account-title-panel">
        <p class="eyebrow">Player Account</p>
        <h1>My Characters</h1>
        <p class="hero-copy">Signed in as ${escapeHtml(req.portalUser.username)}. Review your roster, specs, equipped gear, set bonuses, and raid readiness.</p>
        <span>${rows.length} character${rows.length === 1 ? "" : "s"} on this account</span>
      </div>
    </section>
    ${accountCreated ? `<article class="panel account-created-panel">
      <div>
        <p class="eyebrow">Account Created</p>
        <h2>Your AzerothCore account is ready.</h2>
        <p class="muted">Open the client page when you are ready to download, set your realmlist, and log in with the account you just created.</p>
      </div>
      <a class="button" href="/account/client">Open Client Page</a>
    </article>` : ""}
    <article class="panel account-characters-panel">
      <div class="character-panel-divider" aria-hidden="true"></div>
      <div class="panel-head">
        <h2>My Characters</h2>
        <span>${rows.length} character${rows.length === 1 ? "" : "s"} on this account</span>
      </div>
      ${rows.length ? `<div class="character-results">${renderCharacterCards(rows, gearByGuid, specsByGuid, { showAccount: false })}</div>` : `<p class="muted">No characters exist on this account yet. Create one in game and it will appear here.</p>`}
    </article>`;

  res.send(layout({ title: "My Characters", body, user: req.portalUser }));
});

app.get("/account/client", requireUser, async (req, res) => {
  const body = `
    <section class="page-head account-head download-head">
      <img class="download-page-emblem" src="/portal-art/portal-logo.png" alt="AzerothCore AzerothCore Portal">
      <div>
        <p class="eyebrow">Account Download</p>
        <h1>Game Client</h1>
        <p class="hero-copy">Everything needed to step into AzerothCore: a preconfigured Wrath 3.3.5a HD client with upgraded visuals, plus the launcher for realm news, account status, character data, and future raid tools.</p>
      </div>
    </section>
    <article class="panel download-panel">
      <div class="panel-head"><h2>Downloads</h2><span>Logged-in account access</span></div>
      <div class="download-card">
        <img class="client-box-icon" src="/portal-art/download-icon.png" alt="" aria-hidden="true">
        <div class="download-card-copy">
          <strong>${escapeHtml(clientDownloadName)}</strong>
          <p class="muted">Preconfigured Wrath 3.3.5a HD client for AzerothCore, with upgraded character, creature, mount, armor, world texture, water, map, loading, and login visuals while keeping the classic WotLK gameplay and AzerothCore compatibility.</p>
        </div>
        <a class="button client-download-button" href="/account/download/client"><span>Download Client</span></a>
      </div>
      <div class="download-card">
        <img class="client-box-icon" src="/portal-art/download-icon.png" alt="" aria-hidden="true">
        <div class="download-card-copy">
          <strong>${escapeHtml(launcherDownloadName)}</strong>
          <p class="muted">Launcher package for account status, character data, and AzerothCore updates.</p>
        </div>
        <a class="button launcher-download-button" href="/account/download/launcher"><span>Download Launcher</span></a>
      </div>
    </article>`;

  res.send(layout({ title: "Game Client", body, user: req.portalUser }));
});

app.get("/account/download/client", requireUser, async (req, res) => {
  try {
    const stat = await fs.promises.stat(clientDownloadPath);
    if (!stat.isFile()) throw new Error("Client file is not available on the server.");

    const baseHeaders = downloadHeaders(stat.size, clientDownloadName);
    const range = parseRangeHeader(req.headers.range, stat.size);
    if (req.headers.range && !range) {
      res.setHeader("Content-Range", `bytes */${stat.size}`);
      return res.status(416).end();
    }

    if (range) {
      const chunkSize = range.end - range.start + 1;
      res.writeHead(206, {
        ...baseHeaders,
        "Content-Length": String(chunkSize),
        "Content-Range": `bytes ${range.start}-${range.end}/${stat.size}`
      });
      return fs.createReadStream(clientDownloadPath, { start: range.start, end: range.end }).pipe(res);
    }

    res.writeHead(200, baseHeaders);
    return fs.createReadStream(clientDownloadPath).pipe(res);
  } catch (error) {
    return res.status(404).send(layout({
      title: "Download Unavailable",
      body: `<section class="panel"><h1>Download unavailable</h1><p class="muted">${escapeHtml(error.message)}</p></section>`,
      user: req.portalUser
    }));
  }
});

app.get("/account/download/launcher", requireUser, async (req, res) => {
  try {
    const stat = await fs.promises.stat(launcherDownloadPath);
    if (!stat.isFile()) throw new Error("Launcher file is not available on the server.");

    const baseHeaders = downloadHeaders(stat.size, launcherDownloadName);
    const range = parseRangeHeader(req.headers.range, stat.size);
    if (req.headers.range && !range) {
      res.setHeader("Content-Range", `bytes */${stat.size}`);
      return res.status(416).end();
    }

    if (range) {
      const chunkSize = range.end - range.start + 1;
      res.writeHead(206, {
        ...baseHeaders,
        "Content-Range": `bytes ${range.start}-${range.end}/${stat.size}`,
        "Content-Length": String(chunkSize)
      });
      return fs.createReadStream(launcherDownloadPath, { start: range.start, end: range.end }).pipe(res);
    }

    res.writeHead(200, baseHeaders);
    return fs.createReadStream(launcherDownloadPath).pipe(res);
  } catch (error) {
    return res.status(404).send(layout({
      title: "Download Unavailable",
      body: `<section class="panel"><h1>Download unavailable</h1><p class="muted">${escapeHtml(error.message)}</p></section>`,
      user: req.portalUser
    }));
  }
});

app.get("/admin", requireAdmin, async (_req, res) => {
  const [data, adminHistory] = await Promise.all([
    getPortalData(),
    getAdminActionHistory(6)
  ]);
  data.adminHistory = adminHistory;
  res.send(layout({ title: "AzerothCore Admin", body: renderDashboard(data, true), admin: true, user: currentUser(_req) }));
});

app.get("/admin/realm", requireAdmin, async (req, res) => {
  const [data, realmData] = await Promise.all([
    getPortalData(),
    getAdminRealmData()
  ]);
  res.send(layout({
    title: "Realm & Population",
    body: renderAdminRealmPage(realmData, data),
    admin: true,
    user: currentUser(req)
  }));
});

app.get("/admin/commands", requireAdmin, async (req, res) => {
  const body = `
    <section class="page-head">
      <h1>All Commands</h1>
      <a class="button ghost back-button" href="/admin"><span>Back</span></a>
    </section>
    ${renderAllAdminTools()}`;
  res.send(layout({ title: "All Admin Commands", body, admin: true, user: currentUser(req) }));
});

app.get("/admin/items", requireAdmin, async (req, res) => {
  const search = String(req.query.q || "").trim();
  const [results, characters] = await Promise.all([
    searchAdminItems(search),
    getAdminCharacterChoices()
  ]);
  res.send(layout({
    title: "Admin Items",
    body: renderAdminItemsPage({ search, results, characters }),
    admin: true,
    user: currentUser(req)
  }));
});

app.get("/admin/health", requireAdmin, async (req, res) => {
  const data = await getPortalData();
  const health = await getAdminHealthData(data);
  res.send(layout({
    title: "AzerothCore Health",
    body: renderAdminHealthPage(data, health),
    admin: true,
    user: currentUser(req)
  }));
});

app.get("/admin/raid-roster", requireAdmin, async (req, res) => {
  const rows = await getRaidRosterRows(currentUser(req));
  res.send(layout({ title: "Raid Roster", body: renderRaidRoster(rows), admin: true, user: currentUser(req) }));
});

app.get("/admin/character", requireAdmin, async (req, res) => {
  const search = String(req.query.q || "").trim();
  const normalizedSearch = search.toLowerCase();
  const rows = search
    ? await query(`SELECT c.guid, c.name, c.level, c.race, c.class, c.online, c.map, c.activeTalentGroup,
          c.position_x, c.position_y, c.position_z, c.totalHonorPoints, c.totalKills,
          c.chosenTitle, a.username
        FROM acore_characters.characters c
        JOIN acore_auth.account a ON a.id = c.account
        WHERE LOWER(c.name) LIKE :search
        ORDER BY c.name
        LIMIT 50`, { search: `%${normalizedSearch}%` })
    : [];
  const guids = rows.map(row => Number(row.guid));
  const [gearByGuid, specsByGuid] = await Promise.all([
    getEquippedGear(guids),
    getCharacterSpecs(rows)
  ]);

  const body = `
    <section class="page-head character-lookup-head">
      <div>
        <p class="eyebrow">Character Records</p>
        <h1>Character Lookup</h1>
        <p class="hero-copy">Search characters, review account ownership, spec, location, honor, kills, and equipped gear.</p>
      </div>
      <a class="button ghost back-button" href="/admin"><span>Back</span></a>
    </section>
    <article class="panel character-lookup-panel">
      <form class="lookup" action="/admin/character" method="get">
        <input name="q" value="${escapeHtml(search)}" placeholder="Character name" required>
        <button type="submit">Search</button>
      </form>
      ${search ? `<p class="muted">${rows.length ? `${rows.length} result${rows.length === 1 ? "" : "s"} for "${escapeHtml(search)}"` : `No characters found for "${escapeHtml(search)}"`}</p>` : `<p class="muted">Search by full or partial character name.</p>`}
      <div class="character-results">
        ${renderCharacterCards(rows, gearByGuid, specsByGuid)}
      </div>
    </article>`;

  res.send(layout({ title: "Character Lookup", body, admin: true, user: currentUser(req) }));
});

app.get("/admin/loot", requireAdmin, async (req, res) => {
  try {
    const [runs, serverLoot] = await Promise.all([
      getRaidLootRuns(30),
      getServerRaidLootRuns(30)
    ]);
    res.send(layout({ title: "Raid Loot Tracker", body: renderRaidLootRuns(runs, serverLoot), admin: true, user: currentUser(req) }));
  } catch (error) {
    res.status(500).send(layout({
      title: "Raid Loot Tracker",
      body: `<section class="page-head"><h1>Loot Tracker</h1><a class="button ghost back-button" href="/admin"><span>Back</span></a></section><article class="panel error"><pre>${escapeHtml(error.stack || error.message)}</pre></article>`,
      admin: true,
      user: currentUser(req)
    }));
  }
});

app.get("/admin/loot/server/:runKey", requireAdmin, async (req, res) => {
  try {
    const detail = await getServerRaidLootRunDetail(req.params.runKey);
    res.send(layout({ title: "Server Raid Loot Detail", body: renderServerRaidLootRunDetail(detail), admin: true, user: currentUser(req) }));
  } catch (error) {
    res.status(500).send(layout({
      title: "Server Raid Loot Detail",
      body: `<section class="page-head"><h1>Server Loot Detail</h1><a class="button ghost back-button" href="/admin/loot"><span>Back</span></a></section><article class="panel error"><pre>${escapeHtml(error.stack || error.message)}</pre></article>`,
      admin: true,
      user: currentUser(req)
    }));
  }
});

app.get("/admin/loot/:runId", requireAdmin, async (req, res) => {
  try {
    const runId = Number(req.params.runId);
    if (!Number.isSafeInteger(runId) || runId <= 0) throw new Error("Run ID must be a positive number.");
    const detail = await getRaidLootRunDetail(runId);
    res.send(layout({ title: "Raid Loot Detail", body: renderRaidLootRunDetail(detail), admin: true, user: currentUser(req) }));
  } catch (error) {
    res.status(500).send(layout({
      title: "Raid Loot Detail",
      body: `<section class="page-head"><h1>Loot Detail</h1><a class="button ghost back-button" href="/admin/loot"><span>Back</span></a></section><article class="panel error"><pre>${escapeHtml(error.stack || error.message)}</pre></article>`,
      admin: true,
      user: currentUser(req)
    }));
  }
});

app.get("/admin/advisor", requireAdmin, async (req, res) => {
  res.send(layout({
    title: "AzerothCore Advisor",
    body: renderAdvisorPage({ history: await getAdminActionHistory() }),
    admin: true,
    user: currentUser(req)
  }));
});

app.post("/admin/advisor", requireAdmin, async (req, res) => {
  const reportKey = String(req.body.report || "").trim();
  const report = advisorReports[reportKey];
  const customTask = String(req.body.task || "").trim();
  let response = null;
  let error = "";
  let characterFacts = [];
  let spellFacts = [];

  try {
    const data = await getPortalData();
    characterFacts = customTask ? await getAdvisorCharacterFacts(customTask) : [];
    spellFacts = customTask ? await getAdvisorSpellFacts(customTask, characterFacts) : [];
    if (!report && customTask && unsupportedSpellCastIntent(customTask)) {
      response = {
        ok: true,
        mode: "unsupported-spell-cast",
        stdout: JSON.stringify(unsupportedSpellCastResponse(customTask, spellFacts)),
        stderr: ""
      };
      return res.send(layout({
        title: "AzerothCore Advisor",
        body: renderAdvisorPage({ selected: reportKey, customTask, response, error, characterFacts, spellFacts, history: await getAdminActionHistory() }),
        admin: true,
        user: currentUser(req)
      }));
    }
    if (!report && characterFacts.length && isCharacterInventoryRequest(customTask)) {
      response = {
        ok: true,
        mode: "direct-character-facts",
        stdout: JSON.stringify({
          ready: true,
          risk: "LOW",
          summary: `Loaded current character inventory facts for ${characterFacts.map(character => character.name).join(", ")} directly from the character database. Review the Attached Character Facts section; no model lookup is required for this factual inventory state.`,
          required_facts: [],
          follow_up_questions: [],
          steps: [],
          verification: ["Character matched by name or GUID.", "Inventory rows were loaded from acore_characters.character_inventory joined to item_instance and item_template."],
          rollback: []
        }),
        stderr: ""
      };
      return res.send(layout({
        title: "AzerothCore Advisor",
        body: renderAdvisorPage({ selected: reportKey, customTask, response, error, characterFacts, spellFacts, history: await getAdminActionHistory() }),
        admin: true,
        user: currentUser(req)
      }));
    }
    const inferredAction = !report && customTask ? inferAdvisorAdminAction(customTask) : null;
    if (inferredAction) {
      response = {
        ok: true,
        mode: "direct-admin-action-proposal",
        stdout: JSON.stringify(inferredAction),
        stderr: ""
      };
      return res.send(layout({
        title: "AzerothCore Advisor",
        body: renderAdvisorPage({ selected: reportKey, customTask, response, error, characterFacts, spellFacts, history: await getAdminActionHistory() }),
        admin: true,
        user: currentUser(req)
      }));
    }
    const taskFocus = report
      ? report.task
      : `Request: ${customTask.slice(0, 2000)}`;

    const task = `Answer this AzerothCore-only advisor request using the supplied Portal knowledge profile, portal snapshot, character facts, and admin action catalog.

You must return JSON with these top-level fields:
ready, risk, summary, follow_up_questions, required_facts, steps, verification, rollback.

Make summary the useful plain-English answer for the administrator. Put questions for the administrator in follow_up_questions as direct questions. Keep implementation details short because the portal will hide them behind a details control.

If the request matches one of the catalog actions and all required fields are provided, include this extra top-level JSON property in your normal response:
"proposed_action": {"action":"ACTION_KEY","params":{"field":"value"}}

Use only action keys and field names from the catalog. Do not invent actions, fields, shell commands, SQL, SOAP, GM commands, or Playerbot commands. If required fields are missing, do not include proposed_action; ask for the exact missing fields instead.

Never map a request to cast, use, open, or ask a bot to cast a spell or portal into addItem, Grant Item, learnSpell, or Learn Spell. Only use addItem when the administrator explicitly asks to add/grant/give an item. Only use learnSpell when the administrator explicitly asks to teach/learn a spell.

Protect current Playerbot party, raid, combat, dungeon, rotation, and strategy behavior unless the administrator explicitly asks to change it.

Assignment:
${taskFocus}`;

    if (!report && !customTask) throw new Error("Choose a report or enter a specific advisor question.");

    const advisorTask = `${task}

Portal knowledge profile:
${JSON.stringify(compactPortalKnowledge(), null, 2)}

Portal snapshot:
${JSON.stringify(portalSnapshotForAdvisor(data), null, 2)}

Character facts detected from request:
${JSON.stringify(compactCharacterFactsForAdvisor(characterFacts), null, 2)}

Spell facts detected from request:
${JSON.stringify(compactSpellFactsForAdvisor(spellFacts), null, 2)}

Admin action catalog:
${JSON.stringify(compactAdminActionCatalog(), null, 2)}`;
    response = await advisorGateway("plan", advisorTask);
  } catch (err) {
    error = err.message || String(err);
  }

  res.send(layout({
    title: "AzerothCore Advisor",
    body: renderAdvisorPage({ selected: reportKey, customTask, response, error, characterFacts, spellFacts, history: await getAdminActionHistory() }),
    admin: true,
    user: currentUser(req)
  }));
});

app.post("/admin/advisor/execute", requireAdmin, async (req, res) => {
  const actionKey = String(req.body.action || "").trim();
  const { result, status, customOutput } = await runAdminAction(actionKey, req.body, "advisor");
  const resultState = status === "Action failed" ? "failed" : "success";
  const resultBadge = resultState === "success" ? "Complete" : "Needs Attention";
  const resultHead = adminResultHead(actionKey);

  const body = `
    <section class="page-head"><h1>Advisor Action</h1><a class="button ghost back-button" href="/admin/advisor"><span>Back</span></a></section>
    <article class="panel result-panel ${resultState}">
      <div class="result-hero">
        <div>
          <span class="result-kicker">Approved Advisor Action</span>
          <h2>${escapeHtml(status)}</h2>
        </div>
        <span class="result-pill">${escapeHtml(resultBadge)}</span>
      </div>
      <div class="command-result">
        <div class="command-result-head">
          <span>${escapeHtml(resultHead.title)}</span>
          <small>${escapeHtml(resultHead.subtitle)}</small>
        </div>
        ${customOutput || renderCommandOutput(result, actionKey)}
      </div>
    </article>
    ${renderAdminActionHistory(await getAdminActionHistory())}`;

  res.send(layout({ title: "Advisor Action", body, admin: true, user: currentUser(req) }));
});

app.post("/admin/soap", requireAdmin, async (req, res) => {
  const actionKey = String(req.body.action || "").trim();
  const { result, status, customOutput } = await runAdminAction(actionKey, req.body, "admin");

  const resultState = status === "Action failed" ? "failed" : "success";
  const resultBadge = resultState === "success" ? "Complete" : "Needs Attention";
  const resultHead = adminResultHead(actionKey);
  const resultPanel = renderAdminActionResultPanel({ actionKey, status, resultState, resultBadge, resultHead, customOutput, result });

  if (String(req.body.returnTo || "") === "items") {
    const search = String(req.body.search || "").trim();
    const [results, characters] = await Promise.all([
      searchAdminItems(search),
      getAdminCharacterChoices()
    ]);
    const body = renderAdminItemsPage({ search, results, characters, resultBody: resultPanel });
    return res.send(layout({ title: "Admin Items", body, admin: true, user: currentUser(req) }));
  }

  const body = `
    <section class="page-head"><h1>Server Actions</h1><a class="button ghost back-button" href="/admin"><span>Back</span></a></section>
    ${resultPanel}
    ${renderAdminHub()}`;

  res.send(layout({ title: "Server Actions", body, admin: true, user: currentUser(req) }));
});

app.get("/api/status", async (_req, res) => {
  try {
    res.json(await getPortalData());
  } catch (error) {
    res.status(503).json({
      ok: false,
      realm: realmName,
      error: error.message || "Portal data is unavailable. Check database and SOAP configuration."
    });
  }
});

app.post("/api/launcher/auth/login", requireLauncherHttps, async (req, res) => {
  try {
    await ensurePortalTables();
    const username = cleanAccountName(req.body.username);
    const password = String(req.body.password || "");
    const deviceName = cleanDeviceName(req.body.deviceName);

    if (!launcherLoginRateLimit(req, username)) {
      return jsonError(res, 429, "Too many launcher login attempts. Try again later.");
    }

    const rows = await query("SELECT account_id, username, password_salt, password_hash, last_login FROM acore_auth.portal_users WHERE username = :username LIMIT 1", { username });
    if (!rows.length || !verifyPassword(password, rows[0].password_salt, rows[0].password_hash)) {
      return jsonError(res, 401, "Account name or password did not match.");
    }

    resetLauncherLoginRateLimit(req, username);

    const accessToken = crypto.randomBytes(32).toString("base64url");
    const expiresAtDate = new Date(Date.now() + Math.max(1, launcherTokenDays) * 24 * 60 * 60 * 1000);
    await query(`INSERT INTO acore_auth.portal_launcher_tokens
        (account_id, token_hash, token_prefix, device_name, expires_at)
      VALUES (:accountId, :hash, :prefix, :deviceName, :expiresAt)`, {
      accountId: rows[0].account_id,
      hash: tokenHash(accessToken),
      prefix: accessToken.slice(0, 12),
      deviceName,
      expiresAt: mysqlUtcDate(expiresAtDate)
    });
    await query("UPDATE acore_auth.portal_users SET last_login = CURRENT_TIMESTAMP WHERE account_id = :accountId", { accountId: rows[0].account_id });

    res.json({
      accessToken,
      expiresAt: expiresAtDate.toISOString(),
      account: {
        accountId: Number(rows[0].account_id),
        username: String(rows[0].username || "").toUpperCase(),
        displayName: String(rows[0].username || "").toLowerCase()
      }
    });
  } catch (error) {
    return jsonError(res, 400, error.message || "Launcher login failed.");
  }
});

app.post("/api/launcher/auth/logout", requireLauncherHttps, requireLauncherAuth, async (req, res) => {
  await query("UPDATE acore_auth.portal_launcher_tokens SET revoked_at = UTC_TIMESTAMP() WHERE id = :id", { id: req.launcherUser.tokenId });
  res.json({ ok: true });
});

app.get("/api/launcher/account", requireLauncherHttps, requireLauncherAuth, async (req, res) => {
  const characterCount = await scalar("SELECT COUNT(*) value FROM acore_characters.characters WHERE account = :accountId", { accountId: req.launcherUser.account_id });
  res.json(launcherAccountPayload(req.launcherUser, characterCount));
});

app.get("/api/launcher/characters", requireLauncherHttps, requireLauncherAuth, async (req, res) => {
  const rows = await getLauncherCharacters(req.launcherUser.account_id);
  const [gearSummaries, specsByGuid] = await Promise.all([
    getLauncherGearSummaries(rows.map(row => Number(row.guid))),
    getCharacterSpecs(rows)
  ]);
  res.json({ characters: rows.map(row => {
    const guid = Number(row.guid);
    return launcherCharacterPayload(row, gearSummaries.get(guid), specsByGuid.get(guid));
  }) });
});

app.get("/api/launcher/characters/:guid", requireLauncherHttps, requireLauncherAuth, async (req, res) => {
  const guid = Number(req.params.guid);
  if (!Number.isSafeInteger(guid) || guid <= 0) return jsonError(res, 400, "Character GUID must be a positive number.");
  const rows = await getLauncherCharacters(req.launcherUser.account_id, guid);
  if (!rows.length) return jsonError(res, 404, "Character was not found on this account.");
  const [gearSummaries, specsByGuid] = await Promise.all([
    getLauncherGearSummaries([guid]),
    getCharacterSpecs(rows)
  ]);
  res.json(launcherCharacterPayload(rows[0], gearSummaries.get(guid), specsByGuid.get(guid)));
});

app.post("/api/launcher/raid-loot", requireLauncherHttps, requireLauncherAuth, async (req, res) => {
  try {
    const payload = normalizeLootRunPayload(req.body, req.launcherUser.account_id);
    const result = await saveRaidLootUpload(payload);
    res.json({ ok: true, ...result });
  } catch (error) {
    return jsonError(res, 400, error.message || "Raid loot upload failed.");
  }
});

app.get("/api/launcher/raid-loot/recent", requireLauncherHttps, requireLauncherAuth, async (_req, res) => {
  try {
    const runs = await getRaidLootRuns(10);
    res.json({ runs });
  } catch (error) {
    return jsonError(res, 500, error.message || "Could not read raid loot history.");
  }
});

app.get("/api/launcher/raid-loot/server-recent", requireLauncherHttps, requireLauncherAuth, async (_req, res) => {
  try {
    const result = await getServerRaidLootRuns(20);
    res.json(launcherServerRaidLootPayload(result));
  } catch (error) {
    return jsonError(res, 500, error.message || "Could not read server raid loot history.");
  }
});

app.get("/api/launcher/raid-roster", requireLauncherHttps, requireLauncherAuth, async (req, res) => {
  try {
    const rows = await getRaidRosterRows(req.launcherUser);
    res.json(launcherRaidRosterPayload(rows));
  } catch (error) {
    return jsonError(res, 500, error.message || "Could not read raid roster.");
  }
});

app.get("/api/launcher/realm-population", requireLauncherHttps, requireLauncherAuth, async (_req, res) => {
  try {
    const realmData = await getAdminRealmData();
    res.json(launcherRealmPopulationPayload(realmData));
  } catch (error) {
    return jsonError(res, 500, error.message || "Could not read realm population.");
  }
});

app.get("/api/launcher", async (_req, res) => {
  try {
    res.json(launcherPayload(await getPortalData()));
  } catch (error) {
    res.status(503).json({
      ok: false,
      realm: realmName,
      error: error.message || "Launcher status is unavailable. Check database and SOAP configuration.",
      links: launcherLinks(),
      announcements: launcherAnnouncements()
    });
  }
});

app.listen(port, () => {
  console.log(`AzerothCore portal listening on ${port}`);
});

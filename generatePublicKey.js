var Ed25519KeyIdentity = require("@dfinity/identity").Ed25519KeyIdentity;
var mnemonicToEntropy = require("bip39").mnemonicToEntropy;
var mnemonicToSeedSync = require("bip39").mnemonicToSeedSync;
var validateMnemonic = require("bip39").validateMnemonic;

const IC_DERIVATION_PATH = [44, 223, 0, 0, 0];
const HARDENED = 0x80000000;

async function generateMasterKey(seed) {
  const data = new TextEncoder().encode("ed25519 seed");
  const key = await window.crypto.subtle.importKey(
    "raw",
    data,
    {
      name: "HMAC",
      hash: { name: "SHA-512" },
    },
    false,
    ["sign"]
  );
  const h = await window.crypto.subtle.sign("HMAC", key, seed);
  const slipSeed = new Uint8Array(h.slice(0, 32));
  const chainCode = new Uint8Array(h.slice(32));
  return [slipSeed, chainCode];
}

async function derive(parentKey, parentChaincode, i) {
  // From the spec: Data = 0x00 || ser256(kpar) || ser32(i)
  const data = new Uint8Array([0, ...parentKey, ...toBigEndianArray(i)]);
  const key = await window.crypto.subtle.importKey(
    "raw",
    parentChaincode,
    {
      name: "HMAC",
      hash: { name: "SHA-512" },
    },
    false,
    ["sign"]
  );

  const h = await window.crypto.subtle.sign("HMAC", key, data.buffer);
  const slipSeed = new Uint8Array(h.slice(0, 32));
  const chainCode = new Uint8Array(h.slice(32));
  return [slipSeed, chainCode];
}

// Converts a 32-bit unsigned integer to a big endian byte array.
function toBigEndianArray(n) {
  const byteArray = new Uint8Array([0, 0, 0, 0]);
  for (let i = byteArray.length - 1; i >= 0; i--) {
    const byte = n & 0xff;
    byteArray[i] = byte;
    n = (n - byte) / 256;
  }
  return byteArray;
}

async function fromSeedWithSlip0010(masterSeed, derivationPath = []) {
  let [slipSeed, chainCode] = await generateMasterKey(masterSeed);

  for (let i = 0; i < derivationPath.length; i++) {
    [slipSeed, chainCode] = await derive(
      slipSeed,
      chainCode,
      derivationPath[i] | HARDENED
    );
  }

  return Ed25519KeyIdentity.generate(slipSeed);
}

const parseUserNumber = (s) => {
  if (/^\d+$/.test(s)) {
    try {
      return Number(s);
    } catch (err) {
      return null;
    }
  } else {
    return null;
  }
};

const dropLeadingUserNumber = (s) => {
  const i = s.indexOf(" ");
  if (i !== -1 && parseUserNumber(s.slice(0, i)) !== null) {
    return s.slice(i + 1);
  } else {
    return s;
  }
};


async function calculatePublicKey(seedphrase) {
  const bipWords = dropLeadingUserNumber(seedphrase).trim();
  if (!validateMnemonic(bipWords)) {
    try {
      mnemonicToEntropy(bipWords);
      return "validateMnemonic failed but mnemonicToEntropy didn't give an error";
    } catch (e) {
      return "validateMnemonic failed" + e;
    }
  } else {
    const seed = mnemonicToSeedSync(bipWords);
    const identity = await fromSeedWithSlip0010(seed, IC_DERIVATION_PATH);
    let values = identity.getKeyPair().publicKey.derKey.values();
    let result = "";
    for (const value of values) {
      result += value + ",";
    }
    return result;
  }
}

module.exports = calculatePublicKey;

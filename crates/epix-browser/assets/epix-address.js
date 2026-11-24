// An EPIX xite address encodes a 20-byte payload with a classic Bech32 checksum.
function isEpixXiteAddress(text) {
  // Four HRP characters, a separator, 32 data words and six checksum words.
  if (typeof text !== "string" || text.length !== 43 || /[^A-Za-z0-9]/.test(text)) return false;
  const address = text.toLowerCase();
  if (!address.startsWith("epix1") || (text !== address && text !== text.toUpperCase())) return false;

  const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  function addWord(word) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ word;
    for (let bit = 0; bit < generators.length; bit++) {
      if ((top >>> bit) & 1) checksum ^= generators[bit];
    }
  }

  // BIP-173 expands the HRP into its high bits, a zero, then its low bits.
  const hrp = "epix";
  for (const letter of hrp) addWord(letter.charCodeAt(0) >>> 5);
  addWord(0);
  for (const letter of hrp) addWord(letter.charCodeAt(0) & 31);
  for (const letter of address.slice(hrp.length + 1)) {
    const word = alphabet.indexOf(letter);
    if (word < 0) return false;
    addWord(word);
  }
  return checksum === 1;
}

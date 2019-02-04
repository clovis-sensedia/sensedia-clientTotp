// Estas rotinas utilizam a versão ainda não padronizada da biblioteca Web Crypto
// https://developer.mozilla.org/pt-BR/docs/Web/API/SubtleCrypto
// https://developer.mozilla.org/pt-BR/docs/Web/API/Crypto
// https://www.w3.org/TR/WebCryptoAPI/#subtlecrypto-interface

/**
 * Transforma um array de bytes para uma string contendo a represetação hexa de cada byte.
 * Dobra o tamanho pois cada byte é representado por 2 caracteres hexa.
 */
function buf2hex(buffer) {
  return Array.prototype.slice
    .call(new Uint8Array(buffer))
    .map(x => [x >> 4, x & 15])
    .map(ab => ab.map(x => x.toString(16)).join(""))
    .join("");
}
/**
 * Reverte a função anterior.
 */
function hex2buf(hexStr) {
  return new Uint8Array(hexStr.match(/.{2}/g).map(h => parseInt(h, 16)));
}
/**
 * Deriva uma chava criptográfica a partir de um texto (senha) usando 'PBKDF2' com SHA256 em 1000 iterações.
 * Retorna um array contendo o par '[chave, salt]'.
 */
function deriveKey(passphrase, salt) {
  salt = salt || crypto.getRandomValues(new Uint8Array(8));
  return crypto.subtle
    .importKey("raw", new TextEncoder("utf-8").encode(passphrase), "PBKDF2", false, ["deriveKey"])
    .then(key =>
      crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 1000, hash: "SHA-256" },
        key,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      ),
    )
    .then(key => [key, salt]);
}
/**
 * Deriva uma chave a partir da senha (passphrase), então encripta o texto usando AES-GCM.
 * retorna o texto criptografado concatenado com o salt e o iv no formato "salt-iv-ciphertext"
 */
function encrypt(passphrase, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder("utf-8").encode(plaintext);
  return deriveKey(passphrase).then(([key, salt]) =>
    crypto.subtle
      .encrypt({ name: "AES-GCM", iv }, key, data)
      .then(ciphertext => `${buf2hex(salt)}-${buf2hex(iv)}-${buf2hex(ciphertext)}`),
  );
}

/**
 * Decriptografa o buffer no formato "salt-iv-ciphertext" usando uma chave derivada da passphrase.
 */
function decrypt(passphrase, saltIvCipherHex) {
  const [salt, iv, data] = saltIvCipherHex.split("-").map(hex2buf);
  return deriveKey(passphrase, salt)
    .then(([key]) => {
      var alg = { name: "AES-GCM", iv };
      var v = crypto.subtle.decrypt(alg, key, data);
      return v;
    })
    .then(v => {
      var resp = new TextDecoder("utf-8").decode(new Uint8Array(v));
      return resp;
    });
}



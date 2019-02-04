/**
 * cria a chave secreta TOTP
 */
function newTOTPKey(callback) {
  crypto.subtle.generateKey(
    {
        name: "HMAC",
        hash: {name: "SHA-1"},
    },
    true, //whether the key is extractable (i.e. can be used in exportKey)
    ["sign", "verify"]
  )
  .then(function(key){
    console.log(key);
    window.crypto.subtle.exportKey(
      "raw",
      key
    )
    .then(function(keydata){
      //returns the exported key data
      var keydata = new Int8Array(keydata);
      console.log(keydata);
      //Cria uma versão digitável da chave
      var secret = toBase32(keydata); // 'JBSWY3DPEHPK3PXP';
      callback(secret);
    })
    .catch(function(err){
      console.error(err);
    });
  })
  .catch(function(err){
    console.error(err);
  });
}

function createTOTPs(secret, callback) {
  var epoch = Math.round(new Date().getTime() / 1000.0);
  var time = Math.floor(epoch / 30);
  var key = fromBase32(secret);

  window.crypto.subtle.importKey("raw", key, {name: "HMAC", hash: "SHA-1"}, false, ["sign"])
    .then(key => {
      var promisesToMake = [createTOTP(key, time-1), createTOTP(key, time), createTOTP(key, time+1)]; // calcula 3 OTPs para suportar drifts
      Promise.all(promisesToMake)
        .then(function (hmacs) {
          console.log("success");
          var totps = [];
          for (var i = 0; i < hmacs.length; i++) {
            var hmac = new Int8Array(hmacs[i]);
            var offset = hmac[hmac.length - 1] & 0xf;
            var code = (hmac[offset] & 0x7f) << 24 |
              (hmac[offset + 1] & 0xff) << 16 |
              (hmac[offset + 2] & 0xff) << 8 |
              (hmac[offset + 3] & 0xff);
            code = new Array(7).join('0') + code.toString(10);
            code = code.substr(-6); // 6 dígitos
            totps.push(code);
          }
          callback(totps);
        })
        .catch(e => console.error(e));
    })
    .catch(e => console.error(e));
}
function createTOTP(key, time) {
  // transforma o contador (seegundos / 30) em array de bytes
  var timebuf = new Int8Array(8);
  for (var i = 0; i < 8; i++) {
    timebuf[7 - i] = time & 0xff;
    time = time >> 8;
  }
  return window.crypto.subtle.sign("HMAC", key, timebuf);
}  

function charmap(alphabet, mappings) {
  mappings || (mappings = {});
  alphabet.split("").forEach(function (c, i) {
    if (!(c in mappings)) mappings[c] = i;
  });
  return mappings;
};
var rfc4648 = {
  alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
  charmap: {
    0: 14,
    1: 8
  }
};
rfc4648.charmap = charmap(rfc4648.alphabet, rfc4648.charmap);
/**
 * Cria uma versão digitável da chave
 */
function toBase32(text) {
  var alphabet = rfc4648.alphabet;
  var shift = 3;
  var carry = 0;
  var symbol;
  var byte;
  var i;
  var buf = [];
  for (i = 0; i < text.length; i++) {
    byte = text[i];
    symbol = carry | (byte >> shift);
    buf += alphabet[symbol & 0x1f];
    if (shift > 5) {
      shift -= 5;
      symbol = byte >> shift;
      buf += alphabet[symbol & 0x1f];
    }
    shift = 5 - shift;
    carry = byte << shift;
    shift = 8 - shift;
  }
  if (shift !== 3) {
    buf += alphabet[carry & 0x1f];
  }
  return buf;
}
// Abre a chave TOTP transformando para array de bytes e assim poder usar na API de criptografia
function fromBase32(str) {
  var charmap = rfc4648.charmap;
  var buf = [];
  var shift = 8;
  var carry = 0;
  str.toUpperCase().split("").forEach(function (char) {
    if (char == "=") return;
    // lookup symbol
    var symbol = charmap[char] & 0xff;
    shift -= 5;
    if (shift > 0) {
      carry |= symbol << shift;
    } else if (shift < 0) {
      buf.push(carry | (symbol >> -shift));
      shift += 8;
      carry = (symbol << shift) & 0xff;
    } else {
      buf.push(carry | symbol);
      shift = 8;
      carry = 0;
    }
  });
  if (shift !== 8 && carry !== 0) {
    buf.push(carry);
  }
  var ret = new Int8Array(buf.length);
  for (var i=0;i<buf.length;i++) ret[i] = buf[i];
  return ret;
};


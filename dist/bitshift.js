
function bitShift(conf){

  const def = {
    min: 0,
    max: 255,
    out: 'string',
    padding: [2,2],
    reverse: false,
    iterations: 0
  }
  if(!conf){
    conf = def;
  }

  const MIN = conf.min || def.min,
  MAX = conf.max || def.max,
  OUT = conf.out || def.out;
  PAD = conf.padding || def.padding;
  REV = conf.reverse || def.reverse;
  ITER = conf.iterations || def.iterations;


  const wc = window.crypto,
  wcs = wc.subtle

  const utils = {
    bin2int : s => parseInt(s, 2),
    dec2bin : s => parseInt(s, 10).toString(2),
    hex2int : s => parseInt(s, 16),
    secRand: function(i) {
      return wc.getRandomValues(new Uint32Array(1))[0] / 4294967295 * i;
    },
    randomBytes: function (n) {
      var bytes = new Uint8Array(n)
      for (let i = 0; i < n; i++) {
        bytes[i] = Math.round(utils.secRand(MAX));
      }
      return bytes;
    },
    u82bin: function(byteArray) {
      return Array.from(byteArray, function(byte) {
        return utils.dec2bin(byte);
      })
    },
    bin2u8: function(byteArray) {
      return Uint8Array.from(byteArray, function(byte) {
        return utils.bin2int(byte);
      })//.join('')
    },
    u82s: function(array) {
      return String.fromCharCode.apply(String, array);
    },
    s2u8: function(string) {
      let arrayBuffer = new ArrayBuffer(string.length * 1),
      newUint = new Uint8Array(arrayBuffer);
      newUint.forEach((_, i) => {
        newUint[i] = string.charCodeAt(i);
      });
      return newUint;
    },
    s2a: function(string) {
      let arrayBuffer = new ArrayBuffer(string.length * 1),
      newUint = new Array(arrayBuffer);
      newUint.forEach((_, i) => {
        newUint[i] = string.charCodeAt(i);
      });
      return newUint;
    },
    u82a: function(uint8Array) {
      var array = [];
      for (var i = 0; i < uint8Array.byteLength; i++) {
        array[i] = uint8Array[i];
      }
      return array;
    },
    u82h: function(byteArray){
      return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
      }).join('')
    },
    h2u8: function(str){
      var hexString = str,
      arr = [];
        for (var x = 0; x < hexString.length; x += 2) {
          let num = hexString.substr(x, 2);
          arr.push(utils.hex2int(num));
        }
      return new Uint8Array(arr);
    },
    sup: function(i, shift) {
      if ((i + shift) > MAX) {
        i = MIN + i + shift - MAX;
      } else {
        i = i + shift;
      }
      return i;
    },
    sdown: function(i, shift) {
      if ((i - shift) < MIN) {
        i = MAX + i - shift - MIN;
      } else {
        i = i - shift;
      }
      return i;
    },
    isUint8: function(i){
      if(Object.prototype.toString.call(i) === '[object Uint8Array]' && typeof i === 'object'){
        return true
      }
      return false
    },
    isArray: function(i){
      if(Object.prototype.toString.call(i) === '[object Array]'  && typeof i === 'object'){
        return true
      }
      return false
    },
    isString: function(i){
      if(Object.prototype.toString.call(i) === '[object String]' && typeof i === 'string'){
        return true
      }
      return false
    },
    isEqual: function(a,b){
      if(a === b){
        return true
      }
      return false
    },
    padIt: function(src, i){
      let x = utils.randomBytes(src.length + i[0] + i[1])
      x.set(src, i[0])
      return x;
    },
    unPad: function(src, i){
      src = src.slice(i[0],-i[1])
      return src;
    }
  };

  function checkKey(digest, i, cpt){
    digest = digest.toLowerCase();
    try {
      if(cpt === true){
        if(digest !== 'uint8'){
          i = utils.u82a(i)
          if(digest === 'base64'){
            i = btoa(utils.u82s(i));
          } else if (digest === 'hex') {
            i = utils.u82h(i);
          } else if (digest === 'binary') {
            i = utils.u82bin(i);
          } else if (digest === 'bytes') {
            i = utils.u82s(i);
          }
          return i;
        }
        return i;
      } else {
        if(digest !== 'uint8'){
          if(digest === 'base64'){
            i = utils.s2u8(atob(i));
          } else if (digest === 'hex'){
            i = utils.h2u8(i);
          } else if (digest === 'binary'){
            i = utils.bin2u8(i);
          } else if (digest === 'bytes'){
            i = utils.s2u8(i)
          }
          return new Uint8Array(i);
        }
        return i;
      }
    } catch (err) {
      return 'bit-shift encode mismatch';
    }

  }

  const hmac = {
    gen: function(hash, digest, cb){
      if(!cb){
        return 'bitshift hmac gen requires 3 args'
      }
      wcs.generateKey({name: 'HMAC',hash: {name: 'SHA-'+ hash}}, true, ["sign", "verify"]).then(function(key){
          wcs.exportKey("jwk", key).then(function(keydata){
            let final = checkKey(digest, utils.s2u8(keydata.k), true);
            cb(false, final)
          })
          .catch(function(err){
            cb(err, null);
          });
      })
      .catch(function(err){
        cb(err, null);
      });
    },
    genP: function(hash, digest){
      return new Promise(function(resolve, reject){
        hmac.gen(hash, digest, function(err, key){
          if(err){return reject(err)}
          resolve(key);
        })
      })
    },
    sign: function(key, data, hash, digest, cb){
      if(!cb){
        return 'bitshift hmac sign requires 5 args';
      }
      if(utils.isArray(data)){
        data = Uint8Array.from(data)
      }
      if(!utils.isUint8(data)){
        data = utils.s2u8(data)
      }
      key = utils.u82s(checkKey(digest, key, false));
      wcs.importKey(
          "jwk",
          {kty: "oct",k: key,alg: "HS" + hash,ext: true},
          {name: "HMAC", hash: {name: 'SHA-'+ hash}},
          false,
          ["sign"]
      )
      .then(function(skey){
        wcs.sign({name: "HMAC"}, skey, data)
        .then(function(signature){
          signature = checkKey(digest, new Uint8Array(signature), true)
          cb(false, signature);
        })
        .catch(function(err){
          cb(err, null);
        });
      })
      .catch(function(err){
        cb(err, null);
      });
    },
    signP: function(key, data, hash, digest){
      return new Promise(function(resolve, reject){
        hmac.sign(key, data, hash, digest, function(err, sig){
          if(err){return reject(err)}
          resolve(sig);
        })
      })
    },
    verify: function(key, data, sig, hash, digest, cb){
      if(!cb){
        return 'bitshift hmac verify requires 6 args';
      }
      if(utils.isArray(data)){
        data = Uint8Array.from(data)
      }
      if(!utils.isUint8(data)){
        data = utils.s2u8(data)
      }
      key = utils.u82s(checkKey(digest, key, false));
      sig = checkKey(digest, sig, false)
      wcs.importKey(
          "jwk",
          {kty: "oct",k: key, alg: "HS" + hash, ext: true},
          {name: "HMAC", hash: {name: 'SHA-'+ hash}},
          false,
          ["verify"]
      )
      .then(function(skey){
        wcs.verify({name: "HMAC"}, skey, sig, data)
        .then(function(isvalid){
          cb(false, isvalid);
        })
        .catch(function(err){
          cb(err, null);
        });
      })
      .catch(function(err){
        cb(err, null);
      });
    },
    verifyP: function(key, data, sig, hash, digest, cb){
      return new Promise(function(resolve, reject){
        hmac.verify(key, data, sig, hash, digest, function(err, isEqual){
          if(err){return reject(err)}
          resolve(isEqual);
        })
      })
    }
  }

  // encrypt
  function enc(plain, digest) {

    if(utils.isArray(plain)){
      plain = Uint8Array.from(plain)
    } else if (utils.isString(plain)){
      plain = utils.s2u8(plain)
    }

    let pl = plain.length,
    key = utils.randomBytes(pl),
    ctext = new Uint8Array(pl);

    for (let i = 0; i < pl; i++) {
      ctext[i] = utils.sup(plain[i], key[i]);
    }

    for (let x = 0; x < ITER; x++) {
      for (let i = 0; i < pl; i++) {
        ctext[i] = utils.sup(ctext[i], key[i]);
      }
    }

    if(REV){
      ctext = ctext.reverse();
    }

    if(PAD && utils.isArray(PAD) && PAD.length >= 2){
      ctext = utils.padIt(ctext, PAD)
    }

    return {
      ctext: checkKey(digest, ctext, true),
      key: checkKey(digest, key, true)
    };
  }

  function dec(ctext, key, digest) {

    ctext = checkKey(digest, ctext, false),
    key = checkKey(digest, key, false)

    //remove padding
    if(PAD && utils.isArray(PAD) && PAD.length >= 2){
      ctext = utils.unPad(ctext, PAD)
    }

    if(REV){
      ctext = ctext.reverse();
    }

    let plain = ctext.subarray();

    for (let i = 0; i < ctext.length; i++) {
      plain[i] = utils.sdown(ctext[i], key[i]);
    }

    for (let x = 0; x < ITER; x++) {
      for (let i = 0; i < ctext.length; i++) {
        plain[i] = utils.sdown(plain[i], key[i]);
      }
    }

    if(OUT === 'string'){
      return utils.u82s(plain);
    } else if(OUT === 'array'){
      return utils.u82a(plain);
    }
    return plain;

  }

  return {
    encSync: enc,
    decSync: dec,
    enc: function(plain, digest, cb){
      try {
        cb(false, enc(plain, digest))
        return;
      } catch (err) {
        cb('bit-shift encrypt error', null)
      }
    },
    dec: function(ctext, key, digest, cb){
      try {
        cb(false, dec(ctext, key, digest))
        return;
      } catch (err) {
        cb('bit-shift decrypt error', null)
      }
    },
    encHmac: function(plain, hkey, hash, digest, cb){
      try {
        const data = enc(plain, digest)
        hmac.sign(hkey, data.ctext, hash, digest, function(err, sig){
          if(err){return ce(err)}
          data.hmac = sig;
          cb(false, data)
        })
        return;
      } catch (err) {
        cb('bit-shift encrypt error', null)
      }
    },
    decHmac: function(ctext, key, sig, hkey, hash, digest, cb){
      try {
        hmac.verify(hkey, ctext, sig, hash, digest, function(err, isEqual){
          if(err){return cb(err, null)}
          if(isEqual){
            const plain = dec(ctext, key, digest);
            cb(false, plain)
            return;
          } else {
            cb('bit-shift hmac authentication failure', null)
          }
        })
      } catch (err) {
        cb('bit-shift decrypt error', null)
      }
    },
    encP: function(plain, digest){
      return new Promise(function(resolve, reject){
        try {
          let res = enc(plain, digest)
          resolve(res);
        } catch (err) {
          reject('bit-shift encrypt error');
        }
      })
    },
    decP: function(ctext, key, digest){
      return new Promise(function(resolve, reject){
        try {
          let res = dec(ctext, key, digest)
          resolve(res);
        } catch (err) {
          reject('bit-shift decrypt error');
        }
      })
    },
    encHmacP: function(plain, hkey, hash, digest){
      return new Promise(function(resolve, reject){
        try {
          const data = enc(plain, digest)
          hmac.sign(hkey, data.ctext, hash, digest, function(err, sig){
            if(err){return reject(err)}
            data.hmac = sig;
            resolve(data)
          })
          return;
        } catch (err) {
          reject('bit-shift encrypt hmac error');
        }
      })
    },
    decHmacP: function(ctext, key, sig, hkey, hash, digest){
      return new Promise(function(resolve, reject){
        try {
          hmac.verify(hkey, ctext, sig, hash, digest, function(err, isEqual){
            if(err){return reject(err)}
            if(isEqual){
              const plain = dec(ctext, key, digest);
              resolve(plain)
              return;
            } else {
              reject('bit-shift hmac authentication failure')
            }
          })
        } catch (err) {
          reject('bit-shift decrypt error');
        }
      })
    },
    utils: utils,
    hmac:hmac
  }

}

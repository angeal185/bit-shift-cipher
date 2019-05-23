# bit-shift-cipher

demo: https://angeal185.github.io/bit-shift-cipher/

### Installation

npm

```sh
$ npm install bit-shift-cipher --save
```

bower

```sh
$ bower install bit-shift-cipher
```

git
```sh
$ git clone git@github.com:angeal185/bit-shift-cipher.git
```

#### browser

```html
<script src="./dist/bitshift.min.js"></script>
```



#### API

```js
//default options
{
  min: 0, //min shift
  max: 255, //max shift
  out: 'string' //default decrypt encoding string/array/uint8
}


const conf = {
  out: 'uint8'
},
bsc = new bitShift(conf),

/* encrypt */

/**
 *  sync ~ encrypt data
 *  @param {string/byteArray/uint8Array} plain ~ data to be encrypted
 *  @param {string} digest ~ encrypted data digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/
bsc.encSync(plain,digest)



/**
 *  callback ~ encrypt data
 *  @param {string/byteArray/uint8Array} plain ~ data to be encrypted
 *  @param {string} digest ~ encrypted data digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

bsc.enc(plain, digest, cb)


/**
 *  promise ~ encrypt data
 *  @param {string/byteArray/uint8Array} plain ~ data to be encrypted
 *  @param {string} digest ~ encrypted data digest hex/bytes/binary/uint8/base64
 **/
bsc.encP(plain, digest)


/* decrypt */

/**
 *  sync  ~ decrypt data
 *  @param {string/byteArray/uint8Array} plain ~ data to be decrypted
 *  @param {string/byteArray/uint8Array} key ~ encryption key
 *  @param {string} digest ~ encrypted data digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

bsc.decSync(plain, key, digest)


/**
 *  callback  ~ decrypt data
 *  @param {string/byteArray/uint8Array} plain ~ data to be decrypted
 *  @param {string/byteArray/uint8Array} key ~ encryption key
 *  @param {string} digest ~ encrypted data digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

bsc.dec(plain, key, digest, cb)


/**
 *  promise  ~ decrypt data
 *  @param {string/byteArray/uint8Array} plain ~ data to be encrypted
 *  @param {string/byteArray/uint8Array} key ~ encryption key
 *  @param {string} digest ~ encrypted data digest hex/bytes/binary/uint8/base64
 **/

bsc.decP(plain, key, digest)



/* encrypt with hmac and sign */

/**
 *  callback ~  encrypt and sign
 *  @param {string/byteArray/uint8Array} plain ~ data to encrypt
 *  @param {string/byteArray/uint8Array} hkey ~ hmac key
 *  @param {string} hash ~ hmac hash 256/384/512
 *  @param {string} digest ~ hmac/data digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

bsc.encHmac(plain, hkey, hash, digest, cb)


/**
 *  promise ~  encrypt and sign
 *  @param {string/byteArray/uint8Array} plain ~ data to encrypt
 *  @param {string/byteArray/uint8Array} hkey ~ hmac key
 *  @param {string} hash ~ hmac hash 256/384/512
 *  @param {string} digest ~ hmac/data digest hex/bytes/binary/uint8/base64
 **/

bsc.encHmacP(plain, hkey, hash, digest)



/* verify hmac and decrypt */


/**
 *  callback ~  verify and decrypt
 *  @param {string/byteArray/uint8Array} ctext ~ data to decrypt
 *  @param {string/byteArray/uint8Array} key ~ decrypt key
 *  @param {string/byteArray/uint8Array} hmac ~ hmac signature
 *  @param {string/byteArray/uint8Array} hkey ~ hmac key
 *  @param {string} hash ~ hmac hash 256/384/512
 *  @param {string} digest ~ hmac/data digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

bsc.decHmac(ctext, key, hmac, hkey, hash, digest, cb)


/**
 *  promise ~  verify and decrypt
 *  @param {string/byteArray/uint8Array} ctext ~ data to decrypt
 *  @param {string/byteArray/uint8Array} key ~ decrypt key
 *  @param {string/byteArray/uint8Array} hmac ~ hmac signature
 *  @param {string/byteArray/uint8Array} hkey ~ hmac key
 *  @param {string} hash ~ hmac hash 256/384/512
 *  @param {string} digest ~ hmac/data digest hex/bytes/binary/uint8/base64
 **/

bsc.decHmacP(ctext, key, hmac, hkey, hash, digest)



/* hmac */

/**
 *  callback ~ generate hmac key
 *  @param {string} hash ~ hmac hash 256/384/512
 *  @param {string} digest ~ hmac key digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

bsc.hmac.gen(hash, digest, cb)


/**
 *  promise ~ generate hmac key
 *  @param {string} hash ~ hmac hash 256/384/512
 *  @param {string} digest ~ hmac key digest hex/bytes/binary/uint8/base64
 **/

bsc.hmac.genP(hash, digest)


/**
 *  callback ~ sign encrypted data
 *  @param {string/byteArray/uint8Array} key ~ hmac key
 *  @param {string/byteArray/uint8Array} ctext ~ encrypted data
 *  @param {string} hash ~ hmac hash 256/384/512
 *  @param {string} digest ~ hmac key digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

bsc.hmac.sign(key, ctext, hash, digest, cb)


/**
 *  promise ~ sign encrypted data
 *  @param {string/byteArray/uint8Array} key ~ hmac key
 *  @param {string/byteArray/uint8Array} ctext ~ encrypted data
 *  @param {string} hash ~ hmac hash 256/384/512
 *  @param {string} digest ~ hmac key digest hex/bytes/binary/uint8/base64
 **/

bsc.hmac.signP(key, ctext, hash, digest)


/**
 *  callback ~ verify encrypted data
 *  @param {string/byteArray/uint8Array} key ~ hmac key
 *  @param {string/byteArray/uint8Array} ctext ~ encrypted data
 *  @param {string/byteArray/uint8Array} sig ~ hmac signature
 *  @param {string} hash ~ hmac hash 256/384/512
 *  @param {string} digest ~ hmac key digest hex/bytes/binary/uint8/base64
 **/

bsc.hmac.verify(key, ctext, sig, hash, digest, cb)


/**
 *  promise ~ verify encrypted data
 *  @param {string/byteArray/uint8Array} key ~ hmac key
 *  @param {string/byteArray/uint8Array} ctext ~ encrypted data
 *  @param {string/byteArray/uint8Array} sig ~ hmac signature
 *  @param {string} hash ~ hmac hash 256/384/512
 *  @param {string} digest ~ hmac key digest hex/bytes/binary/uint8/base64
 **/

bsc.hmac.verifyP(key, ctext, sig, hash, digest)


/* utils */

bsc.utils.u82s(Uint8Array) // Uint8Array to string
bsc.utils.s2u8(string) // string to Uint8Array
bsc.utils.u82bin(byteArray) // byteArray to binary
bsc.utils.bin2u8(byteArray) // binary to byteArray
bsc.utils.u82a(uint8Array) // uint8Array to byteArray
bsc.utils.h2u8(i) // hex to Uint8Array
bsc.utils.u82h(i) // uint8Array to hex

bsc.utils.secRand(string) // prng single
bsc.utils.randomBytes(length) // prng filled Uint8Array

bsc.utils.isUint8(i) // check Uint8Array
bsc.utils.isArray(i) // check array
bsc.utils.isString(i) // check string
bsc.utils.isEqual(a,b)  // check if equal

/* demo */

const conf = {
  min: 0,
  max: 255,
  out: 'string'
},
bsc = new bitShift(conf),
utils = bsc.utils,
Digest = 'bytes',
Hash = '256',
cl = console.log,
ce = console.error;


// enc/dec callback
// encrypt data
bsc.enc(text, Digest,function(err, res){
  if(err){return ce(err)}
  // decrypt data
  bsc.dec(res.ctext, res.key, Digest, function(err, dec){
    if(err){return ce(err)}
    cl(dec)
  });
})

// enc/dec promise
// encrypt data
bsc.encP(text, Digest).then(function(res){
  // decrypt data
  bsc.decP(res.ctext, res.key, Digest).then(function(dec){
    cl(dec);
  }).catch(function(err){
    ce('promise dec test failure.')
  })
}).catch(function(err){
  ce(err)
})

// enc/dec with hmac callback
// generate key if needed
bsc.hmac.gen(Hash, Digest, function(err, hkey){
  // encrypt and sign
  bsc.encHmac(text, hkey, Hash, Digest, function(err, res){
    if(err){return ce(err)}
    // verify and decrypt
    bsc.decHmac(res.ctext, res.key, res.hmac, hkey, Hash, Digest, function(err, dec){
      if(err){return ce(err)}
      cl(dec)
    });
  });
})


// enc/dec hmac promise

//generate key if needed
bsc.hmac.gen(Hash, Digest, function(err, hkey){
  // encrypt and sign
  bsc.encHmacP(text, hkey, Hash, Digest)
  .then(function(res){
    // verify and decrypt
    bsc.decHmacP(res.ctext, res.key, res.hmac, hkey, Hash, Digest)
    .then(function(dec){
      cl(dec)
    }).catch(function(err){
      ce(err)
    })
  }).catch(function(err){
    ce(err)
  })
})


//hmac callback

//generate key
bsc.hmac.gen(Hash, Digest, function(err, key){
  if(err){return ce(err)}
  //sign data
  bsc.hmac.sign(key, text, Hash, Digest, function(err, sig){
    if(err){return ce(err)}
    // verify data
    bsc.hmac.verify(key, text, sig, Hash, Digest, function(err, isEqual){
      if(err){return ce(err)}
      cl(isEqual);
    })
  })
})

//hmac promise

//generate key
bsc.hmac.genP(Hash, Digest)
.then(function(key){
  //sign data
  bsc.hmac.signP(key, text, Hash, Digest)
  .then(function(sig){
    // verify data
    bsc.hmac.verifyP(key, text, sig, Hash, Digest)
      .then(function(isEqual){
        cl(isEqual);
      }).catch(function(err){
        ce(err)
      })
  }).catch(function(err){
    ce(err)
  })
}).catch(function(err){
  ce(err)
})

```

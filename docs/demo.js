const conf = {
  min: 0,
  max: 255,
  out: 'string',
  padding: [2,4]
},
bsc = new bitShift(conf),
utils = bsc.utils,
Digest = 'base64',
Hash = '256',
cl = console.log,
ce = console.error;

let dtype = [
  'hex',
  'binary',
  'uint8',
  'base64',
  'bytes'
];

let text = 'abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()-=_+';

function test(type, a, b){
  //test string as input
  if(conf.out === 'string'){
    if(utils.isEqual(a,b)){
      cl(type + ' test pass')
    } else{
      ce(type + ' test fail')
    }
  }
}


  cl(Digest + ' test starting...');
  let sync = bsc.encSync(text, Digest);
  sync = bsc.decSync(sync.ctext, sync.key, Digest);
  //test('sync', sync, text);
  cl(sync)

/*
  //callback
  bsc.enc(text, Digest,function(err, res){
    if(err){return ce(err)}
    cl(res)


    //hmac
    bsc.hmac.gen(Hash, Digest, function(err, key){
      if(err){return ce(err)}

      bsc.hmac.sign(key, res.ctext, Hash, Digest, function(err, sig){
        if(err){return ce(err)}

        bsc.hmac.verify(key, res.ctext, sig, Hash, Digest, function(err, isEqual){
          if(err){return ce(err)}
          test('hamc', isEqual, true);
        })
      })
    })

    bsc.dec(res.ctext, res.key, Digest, function(err, dec){
      if(err){return ce(err)}
      test('callback', dec, text)
    });

  });

  //promise
  bsc.encP(text, Digest).then(function(res){

      bsc.decP(res.ctext, res.key, Digest).then(function(dec){
        test('promise', dec, text);
        cl(Digest + ' test complete.');
      }).catch(function(err){
        ce('promise dec test failure.')
      })

  }).catch(function(err){
    ce(err)
  })

*/

// enc/dec hmac test
/*
bsc.hmac.gen(Hash, Digest, function(err, hkey){

  // cl(hkey)

  bsc.encHmac(text, hkey, Hash, Digest, function(err, res){
    if(err){return ce(err)}
    cl(res)
    bsc.decHmac(res.ctext, res.key, res.hmac, hkey, Hash, Digest, function(err, dec){
      if(err){return ce(err)}
      cl(dec)
    });
  });
})
*/

//hmac callback
/*
bsc.hmac.gen(Hash, Digest, function(err, key){
  if(err){return ce(err)}
  cl(key)
  bsc.hmac.sign(key, text, Hash, Digest, function(err, sig){
    if(err){return ce(err)}

    bsc.hmac.verify(key, text, sig, Hash, Digest, function(err, isEqual){
      if(err){return ce(err)}
      test('hamc', isEqual, true);
    })
  })
})
*/


/*
//hmac promise
bsc.hmac.genP(Hash, Digest)
.then(function(key){
  bsc.hmac.signP(key, text, Hash, Digest)
  .then(function(sig){
    cl(sig)
    bsc.hmac.verifyP(key, text, sig, Hash, Digest)
      .then(function(isEqual){
        test('hamc', isEqual, true);
      }).catch(function(err){
        ce(err)
      })
  }).catch(function(err){
    ce(err)
  })
}).catch(function(err){
  ce(err)
})
*/




// enc/dec hmac promise test
/*
bsc.hmac.gen(Hash, Digest, function(err, hkey){

  // cl(hkey)

  bsc.encHmacP(text, hkey, Hash, Digest)
  .then(function(res){
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
*/

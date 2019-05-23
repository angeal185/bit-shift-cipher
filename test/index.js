const conf = {
  min: 0,
  max: 255
},
bsc = new bitShift(),
utils = bsc.utils,
cl = console.log,
ce = console.error;

function test(type, a, b){
  if(utils.isEqual(a,b)){
    cl(type + ' test pass')
  } else{
    ce(type + ' test fail')
  }
}

function initTest(digest){

  const text = 'abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()-=_+';
  cl(digest + ' test starting...');
  let sync = bsc.encSync(text, digest);
  sync = bsc.decSync(sync.ctext, sync.key, digest);
  test('sync', sync, text);

  //callback
  bsc.enc(text, digest,function(err, res){
    if(err){return ce(err)}


    //hmac
    bsc.hmac.gen('256', digest, function(err, key){
      if(err){return ce(err)}

      bsc.hmac.sign(key, res.ctext, '256', digest, function(err, sig){
        if(err){return ce(err)}

        bsc.hmac.verify(key, res.ctext, sig, '256', digest, function(err, isEqual){
          if(err){return ce(err)}
          test('hamc', isEqual, true);
        })
      })
    })

    bsc.dec(res.ctext, res.key, digest, function(err, dec){
      if(err){return ce(err)}
      test('callback', dec, text)
    });

  });

  //promise
  bsc.encP(text, 'uint8').then(function(res){

      bsc.decP(res.ctext, res.key, 'uint8').then(function(dec){
        test('promise', dec, text);
        cl(digest + ' test complete.');
      }).catch(function(err){
        ce('promise dec test failure.')
      })

  }).catch(function(err){
    ce(err)
  })
}

let dtype = ['hex','binary','uint8','base64','bytes'];

dtype.forEach(function(i){
  initTest(i)
})

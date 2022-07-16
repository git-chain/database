
    var shim = require('./shim');
    // Practical examples about usage found in tests.
    var Encryption = require('./root');
    Encryption.work = require('./work');
    Encryption.sign = require('./sign');
    Encryption.verify = require('./verify');
    Encryption.encrypt = require('./encrypt');
    Encryption.decrypt = require('./decrypt');
    Encryption.certify = require('./certify');

    Encryption.random = Encryption.random || shim.random;

    // For documentation see https://nodejs.org/api/buffer.html
    Encryption.Buffer = Encryption.Buffer || require('./buffer');

    Encryption.keyid = Encryption.keyid || (async (pub) => {
      try {
        // base64('base64(x):base64(y)') => shim.Buffer(xy)
        const pb = shim.Buffer.concat(
          pub.replace(/-/g, '+').replace(/_/g, '/').split('.')
          .map((t) => shim.Buffer.from(t, 'base64'))
        )
        // id is PGPv4 compliant raw key
        const id = shim.Buffer.concat([
          shim.Buffer.from([0x99, pb.length / 0x100, pb.length % 0x100]), pb
        ])
        const sha1 = await sha1hash(id)
        const hash = shim.Buffer.from(sha1, 'binary')
        return hash.toString('hex', hash.length - 8)  // 16-bit ID as hex
      } catch (e) {
        console.log(e)
        throw e
      }
    });

    ((Encryption.window||{}).Database||{}).Encryption = Encryption;

    module.exports = Encryption
  
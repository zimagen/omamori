import Toybox.Cryptography;
import Toybox.Lang;

module Crypto {
    function sha(bytes as ByteArray) as ByteArray {
        var h = new Cryptography.Hash({:algorithm => Cryptography.HASH_SHA256});
        h.update(bytes); return h.digest();
    }
    function hmac(key as ByteArray, bytes as ByteArray) as ByteArray {
        var h = new Cryptography.HashBasedMessageAuthenticationCode({:algorithm => Cryptography.HASH_SHA256, :key => key});
        h.update(bytes); return h.digest();
    }
    // RFC 5869 extract, then the first expand block (v1 always asks for 32 bytes).
    function hkdf(z as ByteArray, salt as ByteArray, info as ByteArray) as ByteArray { return hmac(hmac(salt, z), Proto.cat([info, [1]b])); }
    function equal(a as ByteArray, b as ByteArray) as Boolean {
        if (a.size() != b.size()) { return false; }
        var diff = 0;
        for (var i = 0; i < a.size(); i++) { diff |= a[i] ^ b[i]; }
        return diff == 0;
    }
    function random(n as Number) as ByteArray { return Cryptography.randomBytes(n); }
    function keyPair() as Cryptography.KeyPair { return new Cryptography.KeyPair({:algorithm => Cryptography.KEY_PAIR_ELLIPTIC_CURVE_SECP256R1}); }
    function fromScalar(be as ByteArray) as Cryptography.KeyPair { return new Cryptography.KeyPair({:algorithm => Cryptography.KEY_PAIR_ELLIPTIC_CURVE_SECP256R1, :privateKey => be.reverse()}); }
    function sec1(raw as ByteArray) as ByteArray {
        Proto.require(raw.size() == 64);
        return Proto.cat([[4]b, raw.slice(0,32).reverse(), raw.slice(32,64).reverse()]);
    }
    function rawPublic(sec as ByteArray) as ByteArray {
        Proto.require(sec.size() == 65 && sec[0] == 4);
        return Proto.cat([sec.slice(1,33).reverse(), sec.slice(33,65).reverse()]);
    }
    function publicKey(pair as Cryptography.KeyPair) as ByteArray { return sec1(pair.getPublicKey().getBytes()); }
    function rawSecret(pair as Cryptography.KeyPair, sec as ByteArray) as ByteArray {
        var a = new Cryptography.KeyAgreement({:protocol => Cryptography.KEY_AGREEMENT_ECDH, :privateKey => pair.getPrivateKey()});
        // SDK 9.3 types this parameter as HashAlgorithm, but explicitly
        // requires a KEY_PAIR_ELLIPTIC_CURVE_* value in its documentation.
        a.addKey(Cryptography.createPublicKey(Cryptography.KEY_PAIR_ELLIPTIC_CURVE_SECP256R1 as Cryptography.HashAlgorithm, rawPublic(sec)));
        return a.generateSecret();
    }
    var _reverseSecret = null;
    // SDK documentation does not promise generateSecret byte order. Calibrate
    // once using scalar 1 and the public key for scalar 2 from v1.json.
    // This is public test material, never a session private key.
    function secret(pair as Cryptography.KeyPair, peer as ByteArray) as ByteArray {
        if (_reverseSecret == null) {
            var one = Proto.hex("0000000000000000000000000000000000000000000000000000000000000001");
            var twoPublic = Proto.hex("047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1");
            var expected = twoPublic.slice(1,33);
            var probe = rawSecret(fromScalar(one), twoPublic);
            if (equal(probe, expected)) { _reverseSecret = false; }
            else { Proto.require(equal(probe.reverse(), expected)); _reverseSecret = true; }
        }
        var z = rawSecret(pair, peer);
        Proto.require(z.size() == 32);
        return _reverseSecret ? z.reverse() : z;
    }
}

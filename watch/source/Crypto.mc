import Toybox.Cryptography;
import Toybox.Lang;

// Preserve crypto failures across protocol and BLE exception handlers.
class CryptoError extends Lang.Exception {
    var message as String;
    function initialize(text as String) { Exception.initialize();message=text; }
}

module Crypto {
    function sha(bytes as ByteArray) as ByteArray {
        try {
            var h = new Cryptography.Hash({:algorithm => Cryptography.HASH_SHA256});
            h.update(bytes); return h.digest();
        } catch(e) { throw new CryptoError("Crypto error"); }
    }
    function hmac(key as ByteArray, bytes as ByteArray) as ByteArray {
        try {
            var h = new Cryptography.HashBasedMessageAuthenticationCode({:algorithm => Cryptography.HASH_SHA256, :key => key});
            h.update(bytes); return h.digest();
        } catch(e) { throw new CryptoError("Crypto error"); }
    }
    // RFC 5869 extract, then the first expand block (v1 always asks for 32 bytes).
    function hkdf(z as ByteArray, salt as ByteArray, info as ByteArray) as ByteArray { return hmac(hmac(salt, z), Proto.cat([info, [1]b])); }
    function equal(a as ByteArray, b as ByteArray) as Boolean {
        if (a.size() != b.size()) { return false; }
        var diff = 0;
        for (var i = 0; i < a.size(); i++) { diff |= a[i] ^ b[i]; }
        return diff == 0;
    }
    function random(n as Number) as ByteArray {
        try { return Cryptography.randomBytes(n); }
        catch(e) { throw new CryptoError("Crypto error"); }
    }
    function keyPair() as Cryptography.KeyPair {
        try { return new Cryptography.KeyPair({:algorithm => Cryptography.KEY_PAIR_ELLIPTIC_CURVE_SECP256R1}); }
        catch(e) { throw new CryptoError("Crypto error"); }
    }
    function sec1(raw as ByteArray) as ByteArray {
        Proto.require(raw.size() == 64);
        return Proto.cat([[4]b, raw.slice(0,32).reverse(), raw.slice(32,64).reverse()]);
    }
    function rawPublic(sec as ByteArray) as ByteArray {
        Proto.require(sec.size() == 65 && sec[0] == 4);
        return Proto.cat([sec.slice(1,33).reverse(), sec.slice(33,65).reverse()]);
    }
    function publicKey(pair as Cryptography.KeyPair) as ByteArray {
        try { return sec1(pair.getPublicKey().getBytes()); }
        catch(e) { throw new CryptoError("Crypto error"); }
    }
    function rawSecret(pair as Cryptography.KeyPair, sec as ByteArray) as ByteArray {
        try {
            var a = new Cryptography.KeyAgreement({:protocol => Cryptography.KEY_AGREEMENT_ECDH, :privateKey => pair.getPrivateKey()});
            // SDK 9.3 types this parameter as HashAlgorithm, but explicitly
            // requires a KEY_PAIR_ELLIPTIC_CURVE_* value in its documentation.
            a.addKey(Cryptography.createPublicKey(Cryptography.KEY_PAIR_ELLIPTIC_CURVE_SECP256R1 as Cryptography.HashAlgorithm, rawPublic(sec)));
            return a.generateSecret();
        } catch(e) { throw new CryptoError("Crypto error"); }
    }
    var _reverseSecret = null;
    // SDK documentation does not promise generateSecret byte order. Calibrate
    // once using ECDH(own private, G) == x(own public). Only the session's
    // ephemeral key is used; importing fixed private keys can crash devices.
    function secret(pair as Cryptography.KeyPair, peer as ByteArray) as ByteArray {
        if (_reverseSecret == null) {
            var generator = Proto.hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
            var probe = rawSecret(pair, generator);
            var expected = publicKey(pair).slice(1,33);
            if (equal(probe, expected)) { _reverseSecret = false; }
            else if (equal(probe.reverse(), expected)) { _reverseSecret = true; }
            else { throw new CryptoError("ECDH self-test failed"); }
        }
        var z = rawSecret(pair, peer);
        Proto.require(z.size() == 32);
        return _reverseSecret ? z.reverse() : z;
    }
}

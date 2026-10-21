import Toybox.Lang;
import Toybox.Test;

(:test)
function testEveryCodec(logger) {
    var messages=[Vectors.AUTH_MESSAGE,Vectors.ERROR_MESSAGE,
        Vectors.APPROVAL_PENDING_MESSAGE,Vectors.APPROVAL_APPROVE_MESSAGE,Vectors.APPROVAL_RESULT_MESSAGE,
        Vectors.PAIRING_PAIR_COMMIT_MESSAGE,Vectors.PAIRING_PAIR_HOST_MESSAGE,Vectors.PAIRING_PAIR_REVEAL_MESSAGE,
        Vectors.PAIRING_PAIR_CONFIRM_MESSAGE,Vectors.PAIRING_PAIR_RESULT_MESSAGE];
    for(var i=0;i<messages.size();i++) {var b=Proto.hex(messages[i]);Test.assert(Crypto.equal(b,Proto.encode(Proto.decode(b))));}
    var m=Proto.decode(Proto.hex(Vectors.APPROVAL_PENDING_MESSAGE));var e=m[:entries][0];
    Test.assertEqual(e[:title],Vectors.APPROVAL_TITLE);Test.assertEqual(e[:detail],Vectors.APPROVAL_DETAIL);
    Test.assertEqual(e[:age],Vectors.APPROVAL_AGE_S);Test.assertEqual(e[:kind],Vectors.APPROVAL_KIND);Test.assertEqual(m[:more],false);
    Test.assert(Crypto.equal(Proto.auth(Proto.hex(Vectors.PAIRING_WATCH_NONCE)),Proto.hex(Vectors.AUTH_MESSAGE)));
    Test.assert(Crypto.equal(Proto.pairReveal(Proto.hex(Vectors.PAIRING_WATCH_PUBLIC),Proto.hex(Vectors.PAIRING_WATCH_NONCE),"Venu 4 ⌚"),Proto.hex(Vectors.PAIRING_PAIR_REVEAL_MESSAGE)));
    return true;
}
(:test)
function testFraming(logger) {
    var message=Proto.hex(Vectors.FRAMING_MESSAGE);
    var frames=Proto.frames(message,Vectors.FRAMING_CHUNK_SIZE);
    var expected=[Vectors.FRAMING_CHUNKS_0,Vectors.FRAMING_CHUNKS_1,Vectors.FRAMING_CHUNKS_2,Vectors.FRAMING_CHUNKS_3,Vectors.FRAMING_CHUNKS_4,Vectors.FRAMING_CHUNKS_5,Vectors.FRAMING_CHUNKS_6,Vectors.FRAMING_CHUNKS_7];
    Test.assertEqual(frames.size(),Vectors.FRAMING_CHUNKS_COUNT);var r=new Reassembler();
    for(var i=0;i<frames.size();i++) {Test.assert(Crypto.equal(frames[i],Proto.hex(expected[i])));var b=r.push(frames[i]);if(i<frames.size()-1) {Test.assert(b==null);}else {Test.assert(Crypto.equal(b,message));}}
    var big=[]b;for(var k=0;k<1024;k++) {big.add(k&255);}
    // Chunk size 2 exercises sequence wrap beyond 127.
    var wrapped=Proto.frames(big,2);var out=null;
    for(var j=0;j<wrapped.size();j++) {out=r.push(wrapped[j]);}Test.assert(Crypto.equal(out,big));
    var failed=false;try {r.push([1,9]b);}catch(e) {failed=true;}Test.assert(failed);
    Test.assert(Crypto.equal(r.push([128,9]b),[9]b));
    failed=false;try {Proto.frames(Proto.cat([big,[1]b]),20);}catch(e) {failed=true;}Test.assert(failed);
    failed=false;try {r.push([128]b);}catch(e) {failed=true;}Test.assert(failed);
    failed=false;try {for(var q=0;q<55;q++) {r.push(Proto.cat([[q&127]b,new [19]b]));}}catch(e) {failed=true;}Test.assert(failed);
    return true;
}
(:test)
function testApprovalMacs(logger) {
    var k=Proto.hex(Vectors.PAIRING_KEY);var n=Proto.hex(Vectors.PAIRING_WATCH_NONCE);var h=Proto.hex(Vectors.PAIRING_HOST_ID);
    var p=Proto.decode(Proto.hex(Vectors.APPROVAL_PENDING_MESSAGE));var e=p[:entries][0];
    Test.assert(Crypto.equal(Proto.contents(e),Proto.hex(Vectors.APPROVAL_CONTENTS_HASH)));
    Test.assert(Crypto.equal(Proto.pendingMac(k,n,Proto.hex(Vectors.APPROVAL_PENDING_BEFORE_MAC)),Proto.hex(Vectors.APPROVAL_PENDING_MAC)));
    var mac=Proto.approveMac(k,h,n,e);Test.assert(Crypto.equal(mac,Proto.hex(Vectors.APPROVAL_APPROVE_MAC)));
    Test.assert(Crypto.equal(Proto.approve(e[:id],mac),Proto.hex(Vectors.APPROVAL_APPROVE_MESSAGE)));
    Test.assert(Crypto.equal(Proto.resultMac(k,n,e[:id],0),Proto.hex(Vectors.APPROVAL_RESULT_MAC)));
    e[:detailBytes]=Proto.utf8("different command");Test.assert(!Crypto.equal(mac,Proto.approveMac(k,h,n,e)));
    n[0]^=1;Test.assert(!Crypto.equal(Proto.pendingMac(k,n,Proto.hex(Vectors.APPROVAL_PENDING_BEFORE_MAC)),p[:mac]));
    return true;
}
(:test)
function testHkdfAndPairing(logger) {
    var k=Proto.derive(Proto.hex(Vectors.PAIRING_ECDH_Z),Proto.hex(Vectors.PAIRING_HOST_NONCE),Proto.hex(Vectors.PAIRING_WATCH_NONCE),Proto.hex(Vectors.PAIRING_HOST_ID));
    Test.assert(Crypto.equal(k,Proto.hex(Vectors.PAIRING_KEY)));
    var commit=Proto.commit(Proto.hex(Vectors.PAIRING_WATCH_PUBLIC),Proto.hex(Vectors.PAIRING_WATCH_NONCE));Test.assert(Crypto.equal(commit,Proto.hex(Vectors.PAIRING_COMMIT)));
    Test.assert(Crypto.equal(Proto.pairCommit(commit),Proto.hex(Vectors.PAIRING_PAIR_COMMIT_MESSAGE)));
    var th=Proto.transcript(Proto.hex(Vectors.PAIRING_PAIR_COMMIT_MESSAGE),Proto.hex(Vectors.PAIRING_PAIR_HOST_MESSAGE),Proto.hex(Vectors.PAIRING_PAIR_REVEAL_MESSAGE));
    Test.assert(Crypto.equal(th,Proto.hex(Vectors.PAIRING_TRANSCRIPT_HASH)));Test.assertEqual(Proto.sas(k,th),Vectors.PAIRING_SAS);
    var watch=Proto.confirmMac(k,th,true,true);var host=Proto.confirmMac(k,th,false,true);
    Test.assert(Crypto.equal(watch,Proto.hex(Vectors.PAIRING_WATCH_CONFIRM_MAC)));Test.assert(Crypto.equal(host,Proto.hex(Vectors.PAIRING_HOST_CONFIRM_MAC)));
    Test.assert(Crypto.equal(Proto.pairConfirm(true,watch),Proto.hex(Vectors.PAIRING_PAIR_CONFIRM_MESSAGE)));
    var no=Proto.pairConfirm(false,Proto.confirmMac(k,th,true,false));var decoded=Proto.decode(no);Test.assertEqual(decoded[:accepted],false);Test.assert(!Crypto.equal(decoded[:mac],watch));
    // RFC 5869 case 1, first 32 octets of the expand output.
    var ikm=[]b;for(var i=0;i<22;i++) {ikm.add(0x0b);}
    Test.assert(Crypto.equal(Crypto.hkdf(ikm,Proto.hex("000102030405060708090a0b0c"),Proto.hex("f0f1f2f3f4f5f6f7f8f9")),Proto.hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")));
    return true;
}
(:test)
function testEcdhSimulator(logger) {
    var watch=Crypto.fromScalar(Proto.hex(Vectors.PAIRING_WATCH_PRIVATE_SCALAR));var host=Crypto.fromScalar(Proto.hex(Vectors.PAIRING_HOST_PRIVATE_SCALAR));
    Test.assert(Crypto.equal(Crypto.publicKey(watch),Proto.hex(Vectors.PAIRING_WATCH_PUBLIC)));
    Test.assert(Crypto.equal(Crypto.publicKey(host),Proto.hex(Vectors.PAIRING_HOST_PUBLIC)));
    Test.assert(Crypto.equal(Crypto.sec1(Crypto.rawPublic(Proto.hex(Vectors.PAIRING_WATCH_PUBLIC))),Proto.hex(Vectors.PAIRING_WATCH_PUBLIC)));
    var raw=Crypto.rawSecret(watch,Proto.hex(Vectors.PAIRING_HOST_PUBLIC));var expected=Proto.hex(Vectors.PAIRING_ECDH_Z);
    Test.assert(Crypto.equal(raw,expected) || Crypto.equal(raw.reverse(),expected));
    // secret() detects and normalizes SDK endianness using the fixed vector.
    Test.assert(Crypto.equal(Crypto.secret(watch,Proto.hex(Vectors.PAIRING_HOST_PUBLIC)),expected));
    Test.assert(Crypto.equal(Crypto.secret(host,Proto.hex(Vectors.PAIRING_WATCH_PUBLIC)),expected));
    return true;
}
(:test)
function testMalformedCodecAndUtf8(logger) {
    var good=Proto.hex(Vectors.APPROVAL_PENDING_MESSAGE);
    var bad=[Proto.cat([good,[0]b]),good.slice(0,good.size()-1),[2,1]b,[1,0]b,[1,255,9]b];
    for(var i=0;i<bad.size();i++) {var failed=false;try {Proto.decode(bad[i]);}catch(e) {failed=true;}Test.assert(failed);}
    var unicode="🦀🦀";Test.assertEqual(Proto.text(Proto.stringBytes(unicode,7)),"🦀");
    var malformed=[Proto.hex("02c080"),Proto.hex("03eda080"),Proto.hex("04f4908080"),Proto.hex("01ff"),Proto.hex("02e282")];
    for(var j=0;j<malformed.size();j++) {var invalid=false;try {(new Reader(malformed[j])).stringRaw();}catch(e) {invalid=true;}Test.assert(invalid);}
    return true;
}

import Toybox.Lang;
import Toybox.Test;

(:test)
class SessionSink {
    var messages as Array<ByteArray> = [];var error;var results=0;var stored;var code;var rejectedCount=0;var session;
    function initialize() {}
    function send(b as ByteArray) {messages.add(b);}
    function fail(s) {error=s;if(session!=null) {session.close();}}
    function changed() {}
    function success() {results++;}
    function pairCode(c,name) {code=c;}
    function paired(h) {stored=h;}
    function rejected() {rejectedCount++;}
}

(:test)
function testSessionExplicitTapAndReplay(logger) {
    var sink=new SessionSink();var s=TestFixtures.fixtureSession(sink);
    s.receive(Proto.hex(Vectors.APPROVAL_PENDING_MESSAGE));Test.assertEqual(s.visible().size(),1);Test.assertEqual(sink.messages.size(),1);
    s.tap(Proto.hex(Vectors.APPROVAL_REQ_ID));Test.assertEqual(s.visible().size(),0);Test.assertEqual(sink.messages.size(),2);
    Test.assert(Crypto.equal(sink.messages[1],Proto.hex(Vectors.APPROVAL_APPROVE_MESSAGE)));
    var failed=false;try {s.tap(Proto.hex(Vectors.APPROVAL_REQ_ID));}catch(e) {failed=true;}Test.assert(failed);
    failed=false;try {s.refresh();}catch(e) {failed=true;}Test.assert(failed);
    s.receive(Proto.hex(Vectors.APPROVAL_RESULT_MESSAGE));Test.assertEqual(sink.results,1);
    var old=s.nonce;s.refresh();Test.assert(!Crypto.equal(old,s.nonce));
    failed=false;try {s.receive(Proto.hex(Vectors.APPROVAL_RESULT_MESSAGE));}catch(e) {failed=true;}Test.assert(failed);Test.assert(s.closed);
    return true;
}

(:test)
function testSessionAutomaticOldestAndMore(logger) {
    var sink=new SessionSink();var s=TestFixtures.fixtureSession(sink);
    var p=Proto.hex(Vectors.APPROVAL_PENDING_MESSAGE);
    var young=Proto.decode(p)[:entries][0];young[:flags]=0;young[:age]=10;young[:id]=Proto.hex("1111111111111111");
    var old=Proto.decode(p)[:entries][0];old[:flags]=0;old[:age]=99;old[:id]=Proto.hex("2222222222222222");
    var confirm=Proto.decode(p)[:entries][0];
    s.receive(TestFixtures.fixturePending([young,old,confirm],true));Test.assertEqual(sink.messages.size(),2);
    Test.assert(Crypto.equal(Proto.decode(sink.messages[1])[:id],old[:id]));Test.assert(s.more);Test.assertEqual(s.visible().size(),1);
    return true;
}
(:test)
function testSessionRejectsBadMacNonceHostAndDuplicates(logger) {
    for(var i=0;i<3;i++) {
        var sink=new SessionSink();var s=TestFixtures.fixtureSession(sink);var b=Proto.hex(Vectors.APPROVAL_PENDING_MESSAGE);
        if(i==0) {b[b.size()-1]^=1;}else if(i==1) {s.nonce[0]^=1;}else {s.host[:host_id][0]^=1;}
        s.receive(b);Test.assertEqual(sink.error,"Bad MAC");Test.assertEqual(sink.messages.size(),1);Test.assert(s.closed);
    }
    var target=new SessionSink();var session=TestFixtures.fixtureSession(target);var e=Proto.decode(Proto.hex(Vectors.APPROVAL_PENDING_MESSAGE))[:entries][0];
    var failed=false;try {session.receive(TestFixtures.fixturePending([e,e],false));}catch(ex) {failed=true;}Test.assert(failed);Test.assertEqual(target.messages.size(),1);
    var resultSink=new SessionSink();var resultSession=TestFixtures.fixtureSession(resultSink);resultSession.receive(Proto.hex(Vectors.APPROVAL_PENDING_MESSAGE));resultSession.tap(Proto.hex(Vectors.APPROVAL_REQ_ID));
    var result=Proto.hex(Vectors.APPROVAL_RESULT_MESSAGE);result[result.size()-1]^=1;resultSession.receive(result);Test.assertEqual(resultSink.error,"Bad MAC");Test.assertEqual(resultSink.results,0);
    return true;
}

(:test)
function testPairSessionPersistsOnlyConfirmedResult(logger) {
    var sink=new SessionSink();var s=TestFixtures.fixturePair(sink);
    Test.assertEqual(sink.code,Vectors.PAIRING_SAS);Test.assert(sink.stored==null);
    Test.assert(Crypto.equal(sink.messages[0],Proto.hex(Vectors.PAIRING_PAIR_REVEAL_MESSAGE)));
    s.confirm(true);Test.assert(sink.stored==null);Test.assert(Crypto.equal(sink.messages[1],Proto.hex(Vectors.PAIRING_PAIR_CONFIRM_MESSAGE)));
    s.receive(Proto.hex(Vectors.PAIRING_PAIR_RESULT_MESSAGE));Test.assert(sink.stored!=null);Test.assert(s.closed);
    var badSink=new SessionSink();var bad=TestFixtures.fixturePair(badSink);bad.confirm(true);
    var result=Proto.hex(Vectors.PAIRING_PAIR_RESULT_MESSAGE);result[result.size()-1]^=1;bad.receive(result);Test.assert(badSink.stored==null);Test.assertEqual(badSink.error,"Bad MAC");
    var noSink=new SessionSink();var no=TestFixtures.fixturePair(noSink);no.confirm(false);Test.assert(no.closed);Test.assert(noSink.stored==null);Test.assertEqual(noSink.rejectedCount,1);
    var confirm=Proto.decode(noSink.messages[1]);Test.assertEqual(confirm[:accepted],false);Test.assert(Crypto.equal(confirm[:mac],Proto.confirmMac(Proto.hex(Vectors.PAIRING_KEY),Proto.hex(Vectors.PAIRING_TRANSCRIPT_HASH),true,false)));
    var earlySink=new SessionSink();var early=TestFixtures.fixturePair(earlySink);var failed=false;try {early.receive(Proto.hex(Vectors.PAIRING_PAIR_RESULT_MESSAGE));}catch(e) {failed=true;}Test.assert(failed);Test.assert(earlySink.stored==null);
    return true;
}

(:test)
module TestFixtures {
function fixtureSession(sink as SessionSink) as Session {
    var s=new Session(sink,{:host_id=>Proto.hex(Vectors.PAIRING_HOST_ID),:host_name=>"omamori-pc",:key=>Proto.hex(Vectors.PAIRING_KEY)},false);
    sink.session=s;s.nonce=Proto.hex(Vectors.PAIRING_WATCH_NONCE);s.start();return s;
}
function fixturePending(entries as Array<Entry>,more as Boolean) as ByteArray {
    var p=Proto.decode(Proto.hex(Vectors.APPROVAL_PENDING_MESSAGE));p[:entries]=entries;p[:more]=more;
    var raw=Proto.encode(p);p[:mac]=Proto.pendingMac(Proto.hex(Vectors.PAIRING_KEY),Proto.hex(Vectors.PAIRING_WATCH_NONCE),raw.slice(0,raw.size()-32));return Proto.encode(p);
}
function fixturePair(sink as SessionSink) as Session {
    var s=new Session(sink,null,true);sink.session=s;
    s.nonce=Proto.hex(Vectors.PAIRING_WATCH_NONCE);s.ephemeral=Crypto.fromScalar(Proto.hex(Vectors.PAIRING_WATCH_PRIVATE_SCALAR));
    s.commitMessage=Proto.hex(Vectors.PAIRING_PAIR_COMMIT_MESSAGE);s.pairName="Venu 4 ⌚";
    s.receive(Proto.hex(Vectors.PAIRING_PAIR_HOST_MESSAGE));return s;
}
}

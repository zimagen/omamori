import Toybox.Lang;

// Sans-I/O watch role. No BLE, storage or UI access; send/event via owner.
class Session {
    var owner;var host as Host or Null;var key as Toybox.Lang.ByteArray or Null;var nonce as Toybox.Lang.ByteArray;var pairing;
    var entries as Toybox.Lang.Array<Entry> = [];var sent as Toybox.Lang.Array<Toybox.Lang.ByteArray> = [];var inflight as Toybox.Lang.Array<Flight> = [];var waiting=false;var more=false;var closed=false;
    var ephemeral;var commitMessage;var th;var accepted=null;var pairName="Venu 4";
    function initialize(o,h,p) {owner=o;host=h;pairing=p;nonce=Crypto.random(16);}
    function start() {
        if(pairing) {
            ephemeral=Crypto.keyPair();commitMessage=Proto.pairCommit(Proto.commit(Crypto.publicKey(ephemeral),nonce));owner.send(commitMessage);
        } else {key=host[:key];waiting=true;owner.send(Proto.auth(nonce));}
    }
    function close() {closed=true;key=null;host=null;ephemeral=null;th=null;commitMessage=null;entries=[];inflight=[];}
    function contains(ids as Toybox.Lang.Array<Toybox.Lang.ByteArray>,id as Toybox.Lang.ByteArray) as Boolean {for(var i=0;i<ids.size();i++) {if(Crypto.equal(ids[i],id)) {return true;}}return false;}
    function receive(bytes as ByteArray) {
        try {handle(bytes);}catch(e) {close();throw e;}
    }
    function handle(bytes as ByteArray) {
        Proto.require(!closed);var m=Proto.decode(bytes);var t=m[:type];
        if(t==0xff) {owner.fail(m[:code]==2?"Bad MAC":"PC rejected session");return;}
        if(pairing) {receivePair(m,bytes);return;}
        if(t==0x81 && waiting) {
            if(!Crypto.equal(m[:host],host[:host_id]) || !Crypto.equal(m[:mac],Proto.pendingMac(key,nonce,bytes.slice(0,bytes.size()-32)))) {owner.fail("Bad MAC");return;}
            var ids=[];var next=[];
            for(var i=0;i<m[:entries].size();i++) {var e=m[:entries][i];Proto.require(!contains(ids,e[:id]));ids.add(e[:id]);if(!contains(sent,e[:id])) {next.add(e);}}
            entries=next;waiting=false;more=m[:more];
            var oldest=null as Entry or Null;
            for(var j=0;j<entries.size();j++) {var a=entries[j] as Entry;if(a[:flags]==0 && (oldest==null || a[:age]>(oldest as Entry)[:age])) {oldest=a;}}
            if(oldest!=null) {approve(oldest);}
            owner.changed();
        } else if(t==0x82) {
            var found=null as Flight or Null;var rest=[];
            for(var k=0;k<inflight.size();k++) {var f=inflight[k];if(Crypto.equal(f[:id],m[:id])) {found=f;}else {rest.add(f);}}
            Proto.require(found!=null);
            if(!Crypto.equal(m[:mac],Proto.resultMac(key,found[:nonce],m[:id],m[:status]))) {owner.fail("Bad MAC");return;}
            inflight=rest;
            if(m[:status]!=0) {owner.fail(m[:status]==2?"Bad MAC":"Request expired");return;}
            owner.success();
            // The reference approves one automatic entry per Pending. Refresh
            // for remaining automatic entries only after every Result arrived.
            if(inflight.size()==0 && hasAutomatic()) {refresh();}else {owner.changed();}
        } else {Proto.require(false);}
    }
    function hasAutomatic() {for(var i=0;i<entries.size();i++) {if(entries[i][:flags]==0) {return true;}}return false;}
    function visible() as Toybox.Lang.Array<Entry> {var out=[];for(var i=0;i<entries.size();i++) {if(entries[i][:flags]==1) {out.add(entries[i]);}}return out;}
    function approve(e as Entry) {
        Proto.require(!closed && !pairing && !contains(sent,e[:id]));
        var rest=[];var found=false;
        for(var i=0;i<entries.size();i++) {if(Crypto.equal(entries[i][:id],e[:id])) {found=true;}else {rest.add(entries[i]);}}
        Proto.require(found);
        var msg=Proto.approve(e[:id],Proto.approveMac(key,host[:host_id],nonce,e));
        entries=rest;sent.add(e[:id]);inflight.add({:id=>e[:id],:nonce=>nonce});owner.send(msg);
    }
    function tap(id as Toybox.Lang.ByteArray) {Proto.require(!closed && !pairing);for(var i=0;i<entries.size();i++) {var e=entries[i];if(e[:flags]==1 && Crypto.equal(e[:id],id)) {approve(e);owner.changed();return;}}Proto.require(false);}
    function refresh() {
        Proto.require(!closed && !pairing && !waiting && inflight.size()==0);
        var next=Crypto.random(16);Proto.require(!Crypto.equal(next,nonce));nonce=next;entries=[];waiting=true;owner.send(Proto.auth(nonce));owner.changed();
    }
    function receivePair(m as WireMessage,bytes as Toybox.Lang.ByteArray) {
        if(m[:type]==0x90 && th==null && ephemeral!=null) {
            key=Proto.derive(Crypto.secret(ephemeral,m[:pub]),m[:nonce],nonce,m[:host]);
            var reveal=Proto.pairReveal(Crypto.publicKey(ephemeral),nonce,pairName);ephemeral=null;
            th=Proto.transcript(commitMessage,bytes,reveal);host={:host_id=>m[:host],:host_name=>m[:name],:key=>key};
            owner.send(reveal);owner.pairCode(Proto.sas(key,th),host[:host_name]);
        } else if(m[:type]==0x91) {
            if(!m[:accepted]) {owner.fail("Pairing rejected");return;}
            Proto.require(accepted==true && th!=null);
            if(!Crypto.equal(m[:mac],Proto.confirmMac(key,th,false,true))) {owner.fail("Bad MAC");return;}
            owner.paired(host);close();
        } else {Proto.require(false);}
    }
    function confirm(yes) {
        Proto.require(!closed && pairing && th!=null && accepted==null);accepted=yes;
        owner.send(Proto.pairConfirm(yes,Proto.confirmMac(key,th,true,yes)));
        if(!yes) {close();owner.rejected();}
    }
}

import Toybox.Lang;
import Toybox.StringUtil;

module Proto {
    function require(ok as Boolean) as Void { if (!ok) { throw new Lang.InvalidValueException("Protocol violation"); } }
    function cat(parts as Array<ByteArray>) as ByteArray { var out = []b; for (var i=0; i<parts.size(); i++) { out.addAll(parts[i]); } return out; }
    function hex(s as String) as ByteArray { var out=[]b; for (var i=0;i<s.length();i+=2) { out.add(s.substring(i,i+2).toNumberWithBase(16)); } return out; }
    function utf8(s as String) as ByteArray { return []b.addAll(s.toUtf8Array()); }
    function text(b as ByteArray) as String { var a=[]; for(var i=0;i<b.size();i++) { a.add(b[i]); } return StringUtil.utf8ArrayToString(a); }
    function stringBytes(s as String, limit as Number) as ByteArray {
        var b=utf8(s);
        if(b.size()>limit) {
            var n=limit;
            while(n>0 && (b[n]&0xc0)==0x80) { n--; }
            b=b.slice(0,n);
        }
        return b;
    }
    function str(s as String) as ByteArray { var b=stringBytes(s,255); return cat([[b.size()]b,b]); }
    function u16(n as Number) as ByteArray { return [(n>>8)&255,n&255]b; }
    function message(type as Number, parts as Array<ByteArray>) as ByteArray { var b=cat([[1,type]b,cat(parts)]);require(b.size()<=1024);return b; }
    function auth(nonce as ByteArray) as ByteArray { require(nonce.size()==16); return message(1,[nonce]); }
    function approve(id as ByteArray,mac as ByteArray) as ByteArray { require(id.size()==8 && mac.size()==32);return message(2,[id,mac]); }
    function commit(pub as ByteArray,nonce as ByteArray) as ByteArray { return Crypto.sha(cat([utf8("omamori/v1/commit"),pub,nonce])); }
    function pairCommit(c as ByteArray) as ByteArray { require(c.size()==32);return message(0x10,[c]); }
    function pairReveal(pub as ByteArray,nonce as ByteArray,name as String) as ByteArray { require(pub.size()==65 && nonce.size()==16);return message(0x11,[pub,nonce,str(name)]); }
    function pairConfirm(yes as Boolean,mac as ByteArray) as ByteArray { require(mac.size()==32);return message(0x12,[[yes?1:0]b,mac]); }
    function pendingMac(k as ByteArray,n as ByteArray,b as ByteArray) as ByteArray { return Crypto.hmac(k,cat([utf8("omamori/v1/pending"),n,b])); }
    function contents(e as Entry) as ByteArray { return Crypto.sha(cat([u16(e[:titleBytes].size()),e[:titleBytes],u16(e[:detailBytes].size()),e[:detailBytes]])); }
    function approveMac(k as ByteArray,host as ByteArray,n as ByteArray,e as Entry) as ByteArray { return Crypto.hmac(k,cat([utf8("omamori/v1/approve"),host,n,e[:id],[e[:kind] as Number]b,contents(e)])); }
    function resultMac(k as ByteArray,n as ByteArray,id as ByteArray,status as Number) as ByteArray { return Crypto.hmac(k,cat([utf8("omamori/v1/result"),n,id,[status]b])); }
    function derive(z as ByteArray,hn as ByteArray,wn as ByteArray,id as ByteArray) as ByteArray { return Crypto.hkdf(z,cat([hn,wn]),cat([utf8("omamori/v1/key"),id])); }
    function transcript(c as ByteArray,h as ByteArray,r as ByteArray) as ByteArray { return Crypto.sha(cat([c,h,r])); }
    function sas(k as ByteArray,th as ByteArray) as String {
        var b=Crypto.hmac(k,cat([utf8("omamori/v1/sas"),th]));
        var n=b[0].toLong()*16777216L+b[1].toLong()*65536L+b[2].toLong()*256L+b[3];
        return (n%1000000L).format("%06d");
    }
    function confirmMac(k as ByteArray,th as ByteArray,watch as Boolean,yes as Boolean) as ByteArray { return Crypto.hmac(k,cat([utf8(watch?"omamori/v1/pair-ok/watch":"omamori/v1/pair-ok/host"),th,[yes?1:0]b])); }
    function frames(b as ByteArray,chunk as Number) as Array<ByteArray> {
        require(b.size()>0 && b.size()<=1024 && chunk>=2 && chunk<=20);
        var out=[];var p=0;var seq=0;
        while(p<b.size()) { var end=p+chunk-1; if(end>b.size()) {end=b.size();} out.add(cat([[(seq&127)|(end==b.size()?128:0)]b,b.slice(p,end)]));p=end;seq++; }
        return out;
    }
    function decode(b as ByteArray) as WireMessage {
        require(b.size()<=1024);
        var r=new Reader(b);require(r.byte()==1);var t=r.byte();var m={:type=>t} as WireMessage;
        switch(t) {
            case 1: m[:nonce]=r.take(16);break;
            case 2: m[:id]=r.take(8);m[:mac]=r.take(32);break;
            case 0x10:m[:commit]=r.take(32);break;
            case 0x11:m[:pub]=r.pub();m[:nonce]=r.take(16);m[:name]=r.string();break;
            case 0x12:case 0x91:m[:accepted]=r.boolean();m[:mac]=r.take(32);break;
            case 0x90:m[:pub]=r.pub();m[:nonce]=r.take(16);m[:host]=r.take(16);m[:name]=r.string();break;
            case 0x81:
                m[:host]=r.take(16);m[:name]=r.string();m[:more]=r.boolean();var count=r.byte();var entries=[];
                for(var i=0;i<count;i++) {
                    var e={:id=>r.take(8),:kind=>r.byte(),:flags=>r.byte(),:age=>r.word()} as Entry;
                    require((e[:kind]==1 || e[:kind]==2) && (e[:flags]&254)==0);
                    e[:titleBytes]=r.stringRaw();e[:detailBytes]=r.stringRaw();
                    require(e[:titleBytes].size()<=48 && e[:detailBytes].size()<=160);
                    e[:title]=text(e[:titleBytes]);e[:detail]=text(e[:detailBytes]);entries.add(e);
                }
                m[:entries]=entries;m[:mac]=r.take(32);break;
            case 0x82:m[:id]=r.take(8);m[:status]=r.byte();require(m[:status]<=2);m[:mac]=r.take(32);break;
            case 0xff:m[:code]=r.byte();require(m[:code]>=1 && m[:code]<=4);break;
            default:require(false);
        }
        require(r.pos==b.size());return m;
    }
    // Encoding decoded objects supports byte-for-byte fixture round trips.
    function encode(m as WireMessage) as ByteArray {
        var t=m[:type];var p=[];
        switch(t) {
            case 1:return auth(m[:nonce]);
            case 2:return approve(m[:id],m[:mac]);
            case 0x10:return pairCommit(m[:commit]);
            case 0x11:return pairReveal(m[:pub],m[:nonce],m[:name]);
            case 0x12:return pairConfirm(m[:accepted],m[:mac]);
            case 0x90:p=[m[:pub],m[:nonce],m[:host],str(m[:name])];break;
            case 0x91:p=[[m[:accepted]?1:0]b,m[:mac]];break;
            case 0x82:p=[m[:id],[m[:status] as Number]b,m[:mac]];break;
            case 0xff:p=[[m[:code] as Number]b];break;
            case 0x81:
                p=[m[:host],str(m[:name]),[m[:more]?1:0,m[:entries].size()]b];
                for(var i=0;i<m[:entries].size();i++) {var e=m[:entries][i];p.add(cat([e[:id],[e[:kind] as Number,e[:flags] as Number]b,u16(e[:age]),[e[:titleBytes].size()]b,e[:titleBytes],[e[:detailBytes].size()]b,e[:detailBytes]]));}
                p.add(m[:mac]);break;
            default:require(false);
        }
        return message(t,p);
    }
}
class Reader {
    var bytes as ByteArray;var pos=0;
    function initialize(b as ByteArray) { bytes=b; }
    function take(n as Number) as ByteArray { Proto.require(n>=0 && pos+n<=bytes.size());var b=bytes.slice(pos,pos+n);pos+=n;return b; }
    function byte() as Number { return take(1)[0]; }
    function word() as Number { var b=take(2);return b[0]*256+b[1]; }
    function boolean() as Boolean { var b=byte();Proto.require(b<=1);return b==1; }
    function pub() as ByteArray { var b=take(65);Proto.require(b[0]==4);return b; }
    function stringRaw() as ByteArray {
        var b=take(byte());
        // Reject malformed and noncanonical UTF-8; MACs retain the raw bytes.
        var i=0;
        while(i<b.size()) {
            var c=b[i];i++; if(c<128) {continue;}
            var n=0;var low=128;var high=191;
            if(c>=194 && c<=223) {n=1;}
            else if(c>=224 && c<=239) {n=2;if(c==224){low=160;}if(c==237){high=159;}}
            else if(c>=240 && c<=244) {n=3;if(c==240){low=144;}if(c==244){high=143;}}
            else {Proto.require(false);}
            Proto.require(i+n<=b.size() && b[i]>=low && b[i]<=high);i++;
            for(var j=1;j<n;j++) {Proto.require(b[i]>=128 && b[i]<=191);i++;}
        }
        return b;
    }
    function string() as String { return Proto.text(stringRaw()); }
}
class Reassembler {
    var data=[]b;var seq=0;
    function initialize() {}
    function reset() {data=[]b;seq=0;}
    function push(b as ByteArray) as ByteArray or Null {
        if(b.size()<2 || b.size()>20 || (b[0]&127)!=seq || data.size()+b.size()-1>1024) {reset();Proto.require(false);}
        data.addAll(b.slice(1,b.size()));seq=(seq+1)&127;
        if((b[0]&128)!=0) {var out=data;reset();return out;} return null;
    }
}

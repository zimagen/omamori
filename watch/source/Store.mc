import Toybox.Application;
import Toybox.Lang;
module Store {
    // Application.Storage accepts string dictionary keys, not Symbols.
    // Properties must never be used here: they are cloud synced.
    function hosts() as Array<Host> {
        var value=Application.Storage.getValue("hosts-v1");var out=[] as Array<Host>;
        if(!(value instanceof Array)) {return out;}
        for(var i=0;i<value.size();i++) {
            var h=value[i];if(!(h instanceof Dictionary)) {continue;}
            var id=h["host_id"];var name=h["host_name"];var key=h["key"];
            if(id instanceof ByteArray && id.size()==16 && name instanceof String && key instanceof ByteArray && key.size()==32) {
                out.add({:host_id=>id,:host_name=>name,:key=>key});
            }
        }
        return out;
    }
    function write(list as Array<Host>) as Void {
        var value=[] as Array<Application.Storage.ValueType>;
        for(var i=0;i<list.size();i++) {var h=list[i];var record={} as Dictionary<Application.Storage.KeyType,Application.Storage.ValueType>;record["host_id"]=h[:host_id];record["host_name"]=h[:host_name];record["key"]=h[:key];value.add(record);}
        Application.Storage.setValue("hosts-v1",value);
    }
    function save(host as Host) as Void {
        var list=hosts();var out=[] as Array<Host>;
        for(var i=0;i<list.size();i++) {if(!Crypto.equal(list[i][:host_id],host[:host_id])) {out.add(list[i]);}}
        out.add(host);write(out);
    }
    function remove(id as ByteArray) as Void {
        var list=hosts();var out=[] as Array<Host>;
        for(var i=0;i<list.size();i++) {if(!Crypto.equal(list[i][:host_id],id)) {out.add(list[i]);}}
        write(out);
    }
}

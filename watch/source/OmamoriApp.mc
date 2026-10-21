import Toybox.Application;
import Toybox.Lang;
import Toybox.Attention;
import Toybox.System;
import Toybox.Timer;
import Toybox.WatchUi;

class OmamoriApp extends Application.AppBase {
    var ble;var session;var view;var status="Scanning for PC…";var code;var pairHost;
    var exitTimer;var launchTimer;var finish=false;var rejecting=false;var menuOpen=false;
    function initialize() {AppBase.initialize();exitTimer=new Timer.Timer();launchTimer=new Timer.Timer();}
    function getInitialView() {
        view=new OmamoriView(self);ble=new Ble(self);
        launchTimer.start(method(:launch),100,false);
        return [view,new OmamoriInput(self,view)];
    }
    function launch() {begin(Store.hosts().size()==0);}
    function begin(pair) {
        exitTimer.stop();finish=false;rejecting=false;code=null;pairHost=null;
        if(session!=null) {session.close();}session=null;
        status=pair?"Scanning for pairing PC…":"Scanning for PC…";WatchUi.requestUpdate();ble.start(pair);
    }
    function connecting(host,pair) {status="Connecting…";session=new Session(self,host,pair);WatchUi.requestUpdate();}
    function connected() {status="Authenticating…";session.start();WatchUi.requestUpdate();}
    function send(bytes) {ble.send(bytes);}
    function received(bytes) {
        if(rejecting) {return;}
        if(session==null || session.closed) {fail("Unexpected PC message");return;}
        try {session.receive(bytes);}catch(e) {fail("Invalid PC message");}
    }
    function visible() as Array<Entry> {return session!=null && !session.closed && !session.pairing?session.visible():[];}
    function hasMore() {return session!=null && !session.closed && session.more;}
    function tap(id,hash,n) {
        if(session==null || session.closed || !Crypto.equal(session.nonce,n)) {WatchUi.requestUpdate();return;}
        var list=visible();
        for(var i=0;i<list.size();i++) {var e=list[i];if(Crypto.equal(e[:id],id) && Crypto.equal(Proto.contents(e),hash)) {try {session.tap(id);}catch(ex) {fail("Request unavailable");}return;}}
        WatchUi.requestUpdate();
    }
    function disconnected() {
        if(rejecting || (finish && session!=null && (session.closed || (!session.waiting && session.inflight.size()==0 && session.entries.size()==0 && !session.more)))) {
            ble.stop();exitTimer.stop();exitTimer.start(method(:exit),1500,false);
        }else {fail("Connection lost");}
    }
    function changed() {
        if(session==null || session.closed) {return;}
        if(!session.waiting && session.inflight.size()==0 && visible().size()==0 && !session.hasAutomatic()) {
            if(session.more) {session.refresh();return;}
            status=finish?"Approved":"No pending requests";
            if(finish && !menuOpen) {exitTimer.start(method(:exitIfDone),1500,false);}
        } else if(visible().size()==0) {status=session.waiting?"Refreshing…":"Waiting for PC…";}
        WatchUi.requestUpdate();
    }
    function success() {finish=true;try {Attention.vibrate([new Attention.VibeProfile(40,150)]);}catch(e) {} }
    function pairCode(value,name) {code=value;pairHost=name;status="Compare pairing code";WatchUi.requestUpdate();}
    function confirm(yes) {
        if(code==null || session==null) {return;}code=null;status=yes?"Waiting for PC confirmation…":"Pairing rejected";
        try {session.confirm(yes);}catch(e) {fail("Pairing failed");}WatchUi.requestUpdate();
    }
    function paired(host as Host) {Store.save(host);code=null;status="Paired with "+host[:host_name];success();exitTimer.start(method(:exit),1500,false);WatchUi.requestUpdate();}
    function rejected() {
        // Keep transport alive until the authenticated rejection has drained.
        rejecting=true;exitTimer.start(method(:exitWhenDrained),100,true);WatchUi.requestUpdate();
    }
    function exitWhenDrained() {if(ble.drained()) {exitTimer.stop();ble.stop();exitTimer.start(method(:exit),1500,false);}}
    function fail(message) {
        exitTimer.stop();if(session!=null) {session.close();}if(ble!=null) {ble.stop();}
        code=null;status=message;WatchUi.requestUpdate();exitTimer.start(method(:exit),2500,false);
    }
    function exitIfDone() {if(!menuOpen && session!=null && !session.waiting && session.inflight.size()==0 && session.entries.size()==0 && !session.more) {exit();}}
    function exit() {if(menuOpen) {return;}if(ble!=null) {ble.stop();}System.exit();}
    function onStop(state) {launchTimer.stop();exitTimer.stop();if(session!=null) {session.close();}if(ble!=null) {ble.stop();}}
    function showMenu(title as String,items as Array<MenuRow>,action as String) {
        menuOpen=true;exitTimer.stop();var m=new WatchUi.Menu2({:title=>title});
        for(var i=0;i<items.size();i++) {var it=items[i];m.addItem(new WatchUi.MenuItem(it[:label],it[:sub],it[:id],null));}
        WatchUi.pushView(m,new AppMenuDelegate(self,action),WatchUi.SLIDE_IMMEDIATE);
    }
    function menu() {showMenu("Omamori",[{:label=>"Pair PC",:sub=>null,:id=>"pair"},{:label=>"Refresh",:sub=>null,:id=>"refresh"},{:label=>"Paired PCs",:sub=>null,:id=>"hosts"}],"main");}
    function chooseHost(candidates as Array<Candidate>,pair as Boolean) {
        var items=[];
        for(var i=0;i<candidates.size();i++) {var c=candidates[i];var name=pair?c[:scan].getDeviceName():c[:host][:host_name];if(name==null) {name="Pairing PC";}items.add({:label=>name,:sub=>null,:id=>i});}
        showMenu("Choose PC",items,"choose");
    }
    function menuAction(action,id) {
        menuOpen=false;
        if(action.equals("choose")) {ble.connect(id);}
        else if(action.equals("main")) {
            if(id.equals("pair")) {begin(true);}
            else if(id.equals("hosts")) {
                // Leave the session before deleting a key or changing hosts.
                if(session!=null) {session.close();}ble.stop();code=null;status="Paired PCs";
                var hosts=Store.hosts();var items=[];
                for(var i=0;i<hosts.size();i++) {items.add({:label=>hosts[i][:host_name],:sub=>"Select to delete",:id=>hosts[i][:host_id]});}
                if(items.size()==0) {status="No paired PCs";WatchUi.requestUpdate();}else {showMenu("Paired PCs",items,"delete");}
            } else if(id.equals("refresh")) {
                if(session!=null && !session.closed && !session.pairing) {
                    if(!session.waiting && session.inflight.size()==0) {session.refresh();}
                }else {begin(false);}
            }
        } else if(action.equals("delete")) {showMenu("Delete this PC?",[{:label=>"Delete pairing",:sub=>null,:id=>id}],"remove");}
        else if(action.equals("remove")) {Store.remove(id);status="PC deleted";WatchUi.requestUpdate();}
    }
    function menuBack() {menuOpen=false;changed();}
}

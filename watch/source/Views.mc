import Toybox.Application;
import Toybox.Lang;
import Toybox.Graphics;
import Toybox.WatchUi;

class OmamoriView extends WatchUi.View {
    var owner;var width=0;var page=0;var pages=1;var current=0;var shownId=null;var shownHash;var shownNonce;var shownCode;var shownPairSession;
    function initialize(o) {View.initialize();owner=o;}
    function lines(dc as Graphics.Dc,s as String,maxWidth as Number) as Array<String> {
        var chars=s.toCharArray();var out=[];var line="";
        for(var i=0;i<chars.size();i++) {
            var c=chars[i].toString();
            if(c.equals("\n") || dc.getTextWidthInPixels(line+c,Graphics.FONT_XTINY)>maxWidth) {out.add(line);line="";if(c.equals("\n")) {continue;}}
            line+=c;
        }
        if(line.length()>0) {out.add(line);}return out;
    }
    function onUpdate(dc) {
        dc.setColor(Graphics.COLOR_WHITE,Graphics.COLOR_BLACK);dc.clear();width=dc.getWidth();var height=dc.getHeight();
        dc.drawText(width/2,28,Graphics.FONT_SMALL,"Omamori",Graphics.TEXT_JUSTIFY_CENTER);
        var list=owner.visible() as Array<Entry>;var body=owner.status;var foot="Hold menu for options";
        if(owner.code!=null) {if(shownCode==null || !shownCode.equals(owner.code)) {page=0;}shownCode=owner.code;shownPairSession=owner.session;shownId=null;body=owner.code+"\n"+owner.pairHost+"\nCompare with your PC";foot="Tap accept • Back reject";}
        else if(list.size()>0) {
            if(current>=list.size()) {current=0;}
            var e=list[current];
            var hash=Proto.contents(e);if(shownId==null || !Crypto.equal(shownId,e[:id]) || !Crypto.equal(shownHash,hash)) {page=0;}shownId=e[:id];shownHash=hash;shownNonce=owner.session.nonce;shownCode=null;
            body=e[:title]+"\n"+e[:detail];foot="Tap approve • Swipe next";
        }
        if(list.size()==0 && owner.code==null) {shownId=null;shownCode=null;}
        var wrapped=lines(dc,body,width-100);var lineHeight=dc.getFontHeight(Graphics.FONT_XTINY)+2;var perPage=(height-170)/lineHeight;
        if(perPage<1) {perPage=1;}pages=(wrapped.size()+perPage-1)/perPage;if(pages<1) {pages=1;}if(page>=pages) {page=pages-1;}
        var start=page*perPage;var end=start+perPage;if(end>wrapped.size()) {end=wrapped.size();}
        for(var i=start;i<end;i++) {dc.drawText(width/2,80+(i-start)*lineHeight,Graphics.FONT_XTINY,wrapped[i],Graphics.TEXT_JUSTIFY_CENTER);}
        if(page<pages-1) {foot="Tap to read more";}
        dc.drawText(width/2,height-77,Graphics.FONT_XTINY,foot,Graphics.TEXT_JUSTIFY_CENTER);
        if(list.size()>0) {dc.drawText(width/2,height-48,Graphics.FONT_XTINY,(current+1)+" / "+list.size()+(owner.hasMore()?"  + more":""),Graphics.TEXT_JUSTIFY_CENTER);}
        else if(owner.hasMore()) {dc.drawText(width/2,height-48,Graphics.FONT_XTINY,"+ more — Menu > Refresh",Graphics.TEXT_JUSTIFY_CENTER);}
    }
    function tap() {
        if(page<pages-1) {page++;WatchUi.requestUpdate();return;}
        if(shownCode!=null && owner.code!=null && shownCode.equals(owner.code) && shownPairSession.equals(owner.session)) {owner.confirm(true);shownCode=null;return;}
        if(shownId!=null) {owner.tap(shownId,shownHash,shownNonce);shownId=null;page=0;}
    }
    function next(delta) {var list=owner.visible() as Array<Entry>;if(list.size()>0) {current=(current+delta+list.size())%list.size();page=0;shownId=null;WatchUi.requestUpdate();}}
}
class OmamoriInput extends WatchUi.BehaviorDelegate {
    var owner;var view;
    function initialize(o,v) {BehaviorDelegate.initialize();owner=o;view=v;}
    function onTap(evt) {view.tap();return true;}
    // Deliberately no onSelect approval: approvals require an explicit touch.
    function onSwipe(evt) {view.next(evt.getDirection()==WatchUi.SWIPE_RIGHT?-1:1);return true;}
    function onMenu() {owner.menu();return true;}
    function onBack() {if(owner.code!=null) {owner.confirm(false);}else {owner.exit();}return true;}
}
class AppMenuDelegate extends WatchUi.Menu2InputDelegate {
    var owner;var action;
    function initialize(o,a) {Menu2InputDelegate.initialize();owner=o;action=a;}
    function onSelect(item) {
        WatchUi.popView(WatchUi.SLIDE_IMMEDIATE);owner.menuAction(action,item.getId());
    }
    function onBack() {
        WatchUi.popView(WatchUi.SLIDE_IMMEDIATE);
        owner.menuBack();if(action.equals("choose")) {owner.fail("No PC selected");}
    }
}

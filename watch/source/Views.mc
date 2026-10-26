import Toybox.Application;
import Toybox.Lang;
import Toybox.Graphics;
import Toybox.System;
import Toybox.WatchUi;

class OmamoriView extends WatchUi.View {
    var owner;var width=0;var page=0;var pages=1;var current=0;var shownId=null;var shownHash;var shownNonce;var shownCode;var shownPairSession;var shownAt=0;
    function initialize(o) {View.initialize();owner=o;}
    function onShow() {owner.launch();}
    function lines(dc as Graphics.Dc,s as String,maxWidth as Number,d as Number) as Array<String> {
        var chars=s.toCharArray();var out=[];var line="";
        for(var i=0;i<chars.size();i++) {
            var c=chars[i].toString();
            if(c.equals("\n")) {out.add(line);line="";continue;}
            // Measure each candidate using the renderer that will draw it, including
            // the fallback when a non-ASCII character first enters the line.
            if(line.length()>0 && Pixel.measure(dc,line+c,d)>maxWidth) {out.add(line);line="";}
            line+=c;
        }
        if(line.length()>0) {out.add(line);}return out;
    }
    function onUpdate(dc) {
        dc.setColor(Pixel.FG,Pixel.BG);dc.clear();width=dc.getWidth();var height=dc.getHeight();
        var center=Graphics.TEXT_JUSTIFY_CENTER;var bodyDot=2;
        // These bands fit inside the round screen with margin, including the
        // full rectangle of each glyph (not just its top-left coordinate).
        var contentWidth=width*68/100;var bodyTop=height*36/100;var bodyBottom=height*68/100;
        var headerWidth=Pixel.textWidth("OMAMORI",2);
        var headerX=(width-headerWidth-42)/2;
        Pixel.icon(dc,headerX,height*13/100-6,Pixel.CHARM,2,Pixel.ACCENT);
        Pixel.drawText(dc,headerX+42,height*13/100,"OMAMORI",2,Pixel.ACCENT,Graphics.TEXT_JUSTIFY_LEFT);
        dc.setColor(Pixel.DIM,Pixel.BG);
        for(var x=width*24/100;x<width*76/100;x+=6) {dc.fillRectangle(x,height*23/100,2,2);}
        var list=owner.visible() as Array<Entry>;var body=owner.status;var foot="Tap for menu";
        var color=Pixel.FG;var mark=Pixel.CHARM;
        if(owner.code!=null) {if(shownCode==null || !shownCode.equals(owner.code) || !shownPairSession.equals(owner.session)) {page=0;shownAt=System.getTimer();}shownCode=owner.code;shownPairSession=owner.session;shownId=null;body=owner.pairHost+"\nCompare with your PC";foot="Tap/START accept • BACK reject";
            Pixel.icon(dc,width/2-11,height*26/100,Pixel.KEY,1,Pixel.ACCENT);
            Pixel.drawText(dc,width/2,height*34/100,owner.code,6,Pixel.FG,center);
            bodyTop=height*50/100;color=Pixel.MUTED;
        }
        else if(list.size()>0) {
            if(current>=list.size()) {current=0;}
            var e=list[current];
            var hash=Proto.contents(e);if(shownId==null || !Crypto.equal(shownId,e[:id]) || !Crypto.equal(shownHash,hash) || !Crypto.equal(shownNonce,owner.session.nonce)) {page=0;shownAt=System.getTimer();}shownId=e[:id];shownHash=hash;shownNonce=owner.session.nonce;shownCode=null;
            body=e[:title]+"\n"+e[:detail];foot="Tap/START approve • Swipe next";
            // Wire Kind is Lock=1, Sudo=2.
            mark=e[:kind]==1?Pixel.LOCK:Pixel.TERMINAL;
        }
        if(list.size()==0 && owner.code==null) {shownId=null;shownCode=null;
            if(body.find("Approved")!=null || body.find("Paired with")!=null) {color=Pixel.ACCENT;mark=Pixel.CHECK;}
            else if(body.find("failed")!=null || body.find("error")!=null || body.find("Failed")!=null || body.find("Error")!=null) {mark=Pixel.CROSS;}
        }
        if(owner.code==null) {Pixel.icon(dc,width/2-11,height*27/100,mark,1,color);}
        var timing=[];
        if(list.size()==0 && owner.code==null && owner.timingSummary!=null) {
            timing=lines(dc,owner.timingSummary,contentWidth,1);
            bodyBottom-=timing.size()*16+6;
        }
        var wrapped=lines(dc,body,contentWidth,bodyDot);var lineHeight=Pixel.lineHeight(dc,bodyDot);
        var perPage=(bodyBottom-bodyTop)/lineHeight;
        if(perPage<1) {perPage=1;}pages=(wrapped.size()+perPage-1)/perPage;if(pages<1) {pages=1;}if(page>=pages) {page=pages-1;}
        var start=page*perPage;var end=start+perPage;if(end>wrapped.size()) {end=wrapped.size();}
        var textTop=bodyTop;
        if(list.size()==0 && owner.code==null) {textTop+=(bodyBottom-bodyTop-(end-start)*lineHeight)/2;}
        for(var i=start;i<end;i++) {Pixel.drawText(dc,width/2,textTop+(i-start)*lineHeight,wrapped[i],bodyDot,color,center);}
        for(var t=0;t<timing.size();t++) {Pixel.drawText(dc,width/2,bodyBottom+6+t*16,timing[t],1,Pixel.MUTED,center);}
        if(page<pages-1) {foot="Tap to read more";}
        var footer=lines(dc,foot,contentWidth,1);
        for(var f=0;f<footer.size();f++) {Pixel.drawText(dc,width/2,height*74/100+f*16,footer[f],1,Pixel.MUTED,center);}
        if(list.size()>0) {Pixel.drawText(dc,width/2,height*86/100,(current+1)+" / "+list.size()+(owner.hasMore()?"  + more":""),1,Pixel.MUTED,center);}
        else if(owner.hasMore()) {Pixel.drawText(dc,width/2,height*83/100,"+ more — Menu > Refresh",1,Pixel.MUTED,center);}
    }
    function tap() {
        // A touch can also produce onSelect; give each newly displayed item time to settle.
        if((shownCode!=null || shownId!=null) && System.getTimer()-shownAt<700) {return;}
        if(page<pages-1) {page++;WatchUi.requestUpdate();return;}
        if(shownCode!=null && owner.code!=null && shownCode.equals(owner.code) && shownPairSession.equals(owner.session)) {owner.confirm(true);shownCode=null;return;}
        if(shownId!=null) {owner.tap(shownId,shownHash,shownNonce);shownId=null;page=0;return;}
        menuIfIdle();
    }
    function menuIfIdle() {
        if(page<pages-1 || shownCode!=null || shownId!=null || owner.code!=null || owner.visible().size()>0) {return;}
        owner.menu();
    }
    function next(delta) {var list=owner.visible() as Array<Entry>;if(list.size()>0) {current=(current+delta+list.size())%list.size();page=0;shownId=null;WatchUi.requestUpdate();}}
}
class OmamoriInput extends WatchUi.BehaviorDelegate {
    var owner;var view;
    function initialize(o,v) {BehaviorDelegate.initialize();owner=o;view=v;}
    function onTap(evt) {view.tap();return true;}
    function onSelect() {view.tap();return true;}
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

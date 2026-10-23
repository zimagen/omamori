import Toybox.System;
import Toybox.Lang;

typedef TraceMark as {:label as String, :time as Number};

module Trace {
    var t0=0;var previous=0;
    // Only the latest scan/connection run is retained; times stay app-relative.
    var marks as Array<TraceMark> = [];
    var times as Dictionary<String,Number> = {};
    function initialize() as Void {t0=System.getTimer();previous=0;marks=[];times={};}
    function beginRun() as Void {marks=[];times={};}
    function mark(label as String) as Void {
        var elapsed=System.getTimer()-t0;
        marks.add({:label=>label,:time=>elapsed});times[label]=elapsed;
        System.println("omamori t="+elapsed+" d="+(elapsed-previous)+" "+label);
        previous=elapsed;
    }
    function seconds(ms as Number) as String {return (ms/1000.0).format("%.1f")+"s";}
    function summary() as String or Null {
        var scan=times["scan-start"];var connect=times["connect-start"];
        var cccd=times["cccd-written"];var result=times["result-received"];
        if(scan==null || connect==null || cccd==null || result==null) {return null;}
        return "scan "+seconds(connect-scan)+" conn "+seconds(cccd-connect)+" auth "+seconds(result-cccd);
    }
}

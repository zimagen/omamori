import Toybox.BluetoothLowEnergy;
import Toybox.Timer;
import Toybox.Lang;

class Ble extends BluetoothLowEnergy.BleDelegate {
    var owner;var service;var rxUuid;var txUuid;var device;var rx;var tx;var cccd;
    var firstResult=false;var registered=false;var active=false;var mode=false;var connecting=false;
    var candidates as Array<Candidate> = [];var hosts as Array<Host> = [];var queue as Array<ByteArray> = [];var busy=false;var ready=false;
    var frames;var scanTimer;var collectTimer;var sessionTimer;var writeTimer;
    // Sticky across reconnects and refreshes for this app run.
    // Write-without-response dropped the link on a real Venu 4 (2 of 4 runs:
    // all chunks "acked" locally, PC disconnected before the Approve arrived).
    // Default to with-response; flip to false only for experiments.
    var writeWithResponse=true;
    function initialize(o) {
        BleDelegate.initialize();owner=o;frames=new Reassembler();
        service=BluetoothLowEnergy.stringToUuid("4f6d616d-6f72-6900-0001-000000000000");
        rxUuid=BluetoothLowEnergy.stringToUuid("4f6d616d-6f72-6900-0001-000000000002");
        txUuid=BluetoothLowEnergy.stringToUuid("4f6d616d-6f72-6900-0001-000000000003");
        scanTimer=new Timer.Timer();collectTimer=new Timer.Timer();sessionTimer=new Timer.Timer();writeTimer=new Timer.Timer();
        BluetoothLowEnergy.setDelegate(self);
        BluetoothLowEnergy.registerProfile({:uuid=>service,:characteristics=>[{:uuid=>rxUuid},{:uuid=>txUuid,:descriptors=>[BluetoothLowEnergy.cccdUuid()]}]});
    }
    function start(pair) {
        stop();firstResult=false;mode=pair;hosts=Store.hosts();active=true;
        if(registered) {scan();}
    }
    function scan() {
        try {Trace.mark("scan-start");BluetoothLowEnergy.setScanState(BluetoothLowEnergy.SCAN_STATE_SCANNING);scanTimer.start(method(:scanExpired),15000,false);}
        catch(e) {owner.fail("Bluetooth unavailable");}
    }
    function onProfileRegister(uuid,status) {
        if(status!=BluetoothLowEnergy.STATUS_SUCCESS) {owner.fail("Bluetooth unavailable");return;}
        Trace.mark("profile-registered");registered=true;if(active) {scan();}
    }
    function onScanStateChange(state,status) {if(active && status!=BluetoothLowEnergy.STATUS_SUCCESS) {owner.fail("Bluetooth unavailable");}}
    function onScanResults(results) {
        if(!active || connecting) {return;}
        for(var r=results.next();r!=null;r=results.next()) {
            if(!(r instanceof BluetoothLowEnergy.ScanResult)) {continue;}
            var data=r.getServiceData(service) as ByteArray or Null;if(data==null) {continue;}
            if(!firstResult) {Trace.mark("scan-first-result");firstResult=true;}
            if(data.size()!=9) {continue;}
            if(mode) {if((data[8]&1)!=0) {addCandidate(r,null);}}
            else {for(var i=0;i<hosts.size();i++) {if(Crypto.equal(data.slice(0,8),hosts[i][:host_id].slice(0,8))) {addCandidate(r,hosts[i]);}}}
            if(!active || connecting) {return;}
        }
    }
    function addCandidate(r as BluetoothLowEnergy.ScanResult,h as Host or Null) {
        for(var i=0;i<candidates.size();i++) {if(r.isSameDevice(candidates[i][:scan]) && (h==null || Crypto.equal(h[:host_id],candidates[i][:host][:host_id]))) {return;}}
        Trace.mark("candidate");candidates.add({:scan=>r,:host=>h});
        if(!mode && hosts.size()==1 && h!=null) {choose();return;}
        // Collect a short window so multiple nearby PCs can be chosen.
        if(candidates.size()==1) {collectTimer.start(method(:choose),1200,false);}
    }
    function choose() {
        if(!active) {return;}
        BluetoothLowEnergy.setScanState(BluetoothLowEnergy.SCAN_STATE_OFF);scanTimer.stop();
        if(candidates.size()==1) {connect(0);}else {owner.chooseHost(candidates,mode);}
    }
    function connect(index) {
        if(!active || connecting) {return;}connecting=true;
        try {owner.connecting(candidates[index][:host],mode);if(!active) {return;}sessionTimer.start(method(:expired),60000,false);Trace.mark("connect-start");device=BluetoothLowEnergy.pairDevice(candidates[index][:scan]);if(device==null) {owner.fail("Connection failed");}}
        catch(e) {owner.fail("Connection failed");}
    }
    function onConnectedStateChanged(d,state) {
        if(!active || !connecting) {return;}
        if(device!=null && !d.equals(device)) {return;}
        if(state!=BluetoothLowEnergy.CONNECTION_STATE_CONNECTED) {owner.disconnected();return;}
        Trace.mark("connected");device=d;
        try {
            var s=d.getService(service);Proto.require(s!=null);rx=s.getCharacteristic(rxUuid);tx=s.getCharacteristic(txUuid);Proto.require(rx!=null && tx!=null);
            cccd=tx.getDescriptor(BluetoothLowEnergy.cccdUuid());Proto.require(cccd!=null);Trace.mark("services-ready");busy=true;cccd.requestWrite([1,0]b);
        } catch(e) {owner.fail("PC service unavailable");}
    }
    function onDescriptorWrite(descriptor,status) {
        if(!active || ready || cccd==null || !descriptor.getUuid().equals(cccd.getUuid())) {return;}
        if(status!=BluetoothLowEnergy.STATUS_SUCCESS) {owner.fail("Notifications failed");return;}
        Trace.mark("cccd-written");busy=false;ready=true;owner.connected();pump();
    }
    function send(bytes as ByteArray) {
        var chunks=Proto.frames(bytes,20);for(var i=0;i<chunks.size();i++) {queue.add(chunks[i]);}pump();
    }
    function pump() {
        if(!active || !ready || busy || queue.size()==0) {return;}
        busy=true;
        try {
            if(!writeWithResponse) {writeTimer.start(method(:writeExpired),1500,false);}
            rx.requestWrite(queue[0],{:writeType=>writeWithResponse?BluetoothLowEnergy.WRITE_TYPE_WITH_RESPONSE:BluetoothLowEnergy.WRITE_TYPE_DEFAULT});
        }
        catch(e) {if(!writeWithResponse) {writeFallback();}else {owner.fail("Connection lost");}}
    }
    function writeExpired() {
        if(active && ready && busy && !writeWithResponse) {writeFallback();}
    }
    function writeFallback() {
        writeTimer.stop();writeWithResponse=true;Trace.mark("write-fallback");
        // Keep the current chunk at the head until its retry succeeds.
        busy=false;pump();
    }
    function onCharacteristicWrite(characteristic,status) {
        if(!active || !ready || !characteristic.getUuid().equals(rxUuid) || !busy) {return;}
        writeTimer.stop();
        if(status!=BluetoothLowEnergy.STATUS_SUCCESS) {
            if(!writeWithResponse) {writeFallback();}else {owner.fail("Connection lost");}return;
        }
        queue=queue.slice(1,queue.size());Trace.mark("tx-acked q="+queue.size());busy=false;pump();
    }
    function onCharacteristicChanged(characteristic,value) {
        if(!active || !ready || !characteristic.getUuid().equals(txUuid)) {return;}
        Trace.mark("rx-chunk n="+value.size());
        try {var b=frames.push(value);if(b!=null) {owner.received(b);}}
        catch(e) {owner.fail("Invalid PC message");}
    }
    function scanExpired() {owner.fail(mode?"No pairing PC nearby":"No paired PC nearby");}
    function expired() {owner.fail("Session timed out");}
    function drained() {return queue.size()==0 && !busy;}
    function stop() {
        active=false;scanTimer.stop();collectTimer.stop();sessionTimer.stop();writeTimer.stop();
        BluetoothLowEnergy.setScanState(BluetoothLowEnergy.SCAN_STATE_OFF);
        if(device!=null) {BluetoothLowEnergy.unpairDevice(device);}device=null;rx=null;tx=null;cccd=null;
        queue=[];busy=false;ready=false;connecting=false;candidates=[];hosts=[];frames.reset();
    }
}

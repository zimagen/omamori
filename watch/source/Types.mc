import Toybox.Lang;
typedef Host as {:host_id as ByteArray, :host_name as String, :key as ByteArray};
typedef Entry as {:id as ByteArray, :kind as Number, :flags as Number, :age as Number, :titleBytes as ByteArray, :detailBytes as ByteArray, :title as String, :detail as String};
typedef Flight as {:id as ByteArray, :nonce as ByteArray};
typedef Candidate as {:scan as Toybox.BluetoothLowEnergy.ScanResult, :host as Host or Null};
typedef MenuRow as {:label as String, :sub as String or Null, :id as Object};
// Fields depend on type; decode validates their presence and size before use.
typedef WireMessage as {:type as Number, :nonce as ByteArray, :id as ByteArray, :mac as ByteArray, :commit as ByteArray, :pub as ByteArray, :name as String, :accepted as Boolean, :host as ByteArray, :more as Boolean, :entries as Array<Entry>, :status as Number, :code as Number};

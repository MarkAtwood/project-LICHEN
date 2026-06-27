import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';

/// LICHEN BLE service UUID - nodes advertise this
const String lichenServiceUuid = '6c696368-656e-4d65-7368-000000000001';

/// LICHEN ping characteristic UUID - for health checks
const String lichenPingUuid = '6c696368-656e-4d65-7368-000000000010';

/// Connection states for the BLE manager
enum ConnectionState {
  disconnected,
  scanning,
  connecting,
  connected,
}

/// Manages BLE connection to a LICHEN node
class BleConnection extends ChangeNotifier {
  ConnectionState _state = ConnectionState.disconnected;
  BluetoothDevice? _device;
  StreamSubscription<BluetoothConnectionState>? _connectionSubscription;
  Timer? _reconnectTimer;
  int _reconnectAttempts = 0;
  static const int _maxReconnectDelay = 30;

  /// Current connection state
  ConnectionState get state => _state;

  /// Currently connected device (if any)
  BluetoothDevice? get device => _device;

  /// Stream of connection state changes
  Stream<ConnectionState> get stateStream => _stateController.stream;
  final _stateController = StreamController<ConnectionState>.broadcast();

  /// Whether auto-reconnect is enabled
  bool autoReconnect = true;

  void _setState(ConnectionState newState) {
    if (_state != newState) {
      _state = newState;
      _stateController.add(newState);
      notifyListeners();
    }
  }

  /// Scan for LICHEN nodes
  ///
  /// Returns a stream of discovered devices advertising the LICHEN service.
  /// Call [stopScan] when done or scanning will timeout after [timeout].
  Stream<ScanResult> scan({Duration timeout = const Duration(seconds: 10)}) {
    _setState(ConnectionState.scanning);

    FlutterBluePlus.startScan(
      withServices: [Guid(lichenServiceUuid)],
      timeout: timeout,
    );

    // Reset state when scan completes
    FlutterBluePlus.isScanning.listen((scanning) {
      if (!scanning && _state == ConnectionState.scanning) {
        _setState(ConnectionState.disconnected);
      }
    });

    return FlutterBluePlus.scanResults.expand((results) => results);
  }

  /// Stop scanning for devices
  Future<void> stopScan() async {
    await FlutterBluePlus.stopScan();
    if (_state == ConnectionState.scanning) {
      _setState(ConnectionState.disconnected);
    }
  }

  /// Connect to a LICHEN node
  ///
  /// Establishes BLE connection and sets up auto-reconnect if enabled.
  Future<void> connect(BluetoothDevice device) async {
    _cancelReconnect();
    _device = device;
    _setState(ConnectionState.connecting);

    try {
      await device.connect(
        timeout: const Duration(seconds: 15),
        autoConnect: false,
      );

      _reconnectAttempts = 0;
      _setState(ConnectionState.connected);
      _setupConnectionMonitoring(device);
    } catch (e) {
      debugPrint('BLE connect failed: $e');
      _setState(ConnectionState.disconnected);
      if (autoReconnect) {
        _scheduleReconnect();
      }
    }
  }

  void _setupConnectionMonitoring(BluetoothDevice device) {
    _connectionSubscription?.cancel();
    _connectionSubscription = device.connectionState.listen((state) {
      if (state == BluetoothConnectionState.disconnected) {
        _setState(ConnectionState.disconnected);
        if (autoReconnect && _device != null) {
          _scheduleReconnect();
        }
      } else if (state == BluetoothConnectionState.connected) {
        _reconnectAttempts = 0;
        _setState(ConnectionState.connected);
      }
    });
  }

  void _scheduleReconnect() {
    _cancelReconnect();

    // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s, 30s, ...
    final delay = _reconnectAttempts < 5
        ? Duration(seconds: 1 << _reconnectAttempts)
        : const Duration(seconds: _maxReconnectDelay);

    debugPrint('Scheduling reconnect in ${delay.inSeconds}s (attempt ${_reconnectAttempts + 1})');

    _reconnectTimer = Timer(delay, () {
      _reconnectAttempts++;
      if (_device != null) {
        connect(_device!);
      }
    });
  }

  void _cancelReconnect() {
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
  }

  /// Disconnect from the current device
  Future<void> disconnect() async {
    autoReconnect = false;
    _cancelReconnect();
    _connectionSubscription?.cancel();
    _connectionSubscription = null;

    final device = _device;
    _device = null;

    if (device != null) {
      try {
        await device.disconnect();
      } catch (e) {
        debugPrint('BLE disconnect failed: $e');
      }
    }

    _setState(ConnectionState.disconnected);
  }

  /// Perform health check via ping characteristic
  ///
  /// Returns true if the node responds, false otherwise.
  Future<bool> ping() async {
    if (_state != ConnectionState.connected || _device == null) {
      return false;
    }

    try {
      final services = await _device!.discoverServices();

      for (final service in services) {
        if (service.uuid.toString().toLowerCase() == lichenServiceUuid.toLowerCase()) {
          for (final char in service.characteristics) {
            if (char.uuid.toString().toLowerCase() == lichenPingUuid.toLowerCase()) {
              // Read ping characteristic - any response means node is alive
              await char.read();
              return true;
            }
          }
        }
      }
      return false;
    } catch (e) {
      debugPrint('Ping failed: $e');
      return false;
    }
  }

  @override
  void dispose() {
    _cancelReconnect();
    _connectionSubscription?.cancel();
    _stateController.close();
    super.dispose();
  }
}

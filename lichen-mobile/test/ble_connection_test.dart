import 'package:flutter_test/flutter_test.dart';
import 'package:lichen_mobile/services/ble_connection.dart';

void main() {
  group('BleConnection', () {
    test('initial state is disconnected', () {
      final ble = BleConnection();
      expect(ble.state, ConnectionState.disconnected);
      expect(ble.device, isNull);
      ble.dispose();
    });

    test('auto-reconnect is enabled by default', () {
      final ble = BleConnection();
      expect(ble.autoReconnect, isTrue);
      ble.dispose();
    });

    test('disconnect disables auto-reconnect', () async {
      final ble = BleConnection();
      expect(ble.autoReconnect, isTrue);
      await ble.disconnect();
      expect(ble.autoReconnect, isFalse);
      ble.dispose();
    });
  });

  group('ConnectionState', () {
    test('has all expected values', () {
      expect(ConnectionState.values, containsAll([
        ConnectionState.disconnected,
        ConnectionState.scanning,
        ConnectionState.connecting,
        ConnectionState.connected,
      ]));
    });
  });
}

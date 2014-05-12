#include <XBee.h>
#include "aes256.h"

// ID for this node
uint8_t nodeId[] = { 0x00, 0x01 };

XBee xbee = XBee();
XBeeResponse response = XBeeResponse();

// create reusable response objects for responses we expect to handle
Rx16Response rx16 = Rx16Response();

int notificationLed = 10;
int statusLed = 11;
int errorLed = 12;
int dataLed = 13;
unsigned long timeMillis;

// Create AES context and key
aes256_context ctxt;

uint8_t key[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};

uint8_t androidRequest[32];
uint8_t androidResponse[32];

uint8_t nonceDevice[2];
uint8_t nonceLocal[2];

// 16-bit addressing: Enter address of remote XBee, typically the coordinator
Tx16Request txAndroidResponse = Tx16Request(0xFFFF, androidResponse, sizeof(androidResponse));
TxStatusResponse txStatus = TxStatusResponse();

// Flashes an LED at a given rate
void flashLed(int pin, int times, int wait) {
	for (int i = 0; i < times; i++) {
		digitalWrite(pin, HIGH);
		delay(wait);
		digitalWrite(pin, LOW);

		if (i + 1 < times) {
			delay(wait);
		}
	}
}

// Prints the request data sent by a mobile device that initiates the
// 2FA auth procedure
void printAuthRequestPacket() {
	Serial.print("* Nonce: ");
	Serial.print(androidRequest[0], HEX);
	Serial.println(androidRequest[1], HEX);

	Serial.print("* Device ID: ");
	for (uint8_t i = 2; i < 10; i++) {
		Serial.print(androidRequest[i], HEX);
	}
	Serial.println();

	Serial.print("* Node ID: ");
	Serial.print(androidRequest[10], HEX);
	Serial.println(androidRequest[11], HEX);

	Serial.print("* Timestamp: ");
	Serial.print(androidRequest[12], HEX);
	Serial.print(androidRequest[13], HEX);
	Serial.print(androidRequest[14], HEX);
	Serial.println(androidRequest[15], HEX);
}

// Creates a response to the 2FA auth request
void createAuthResponsePacket() {
	// Node ID
	androidResponse[0] = 0x00;
	androidResponse[1] = 0x01;

	// Device ID (e.g., IMEI)
	// Get from AuthRequest
	for (uint8_t i = 2; i < 10; i++) {
		androidResponse[i] = androidRequest[i];
	}

	// Nonce (Fio)
	// Generate a random number
	nonceLocal = { 0x00, uint8_t(random(255)) };
	androidResponse[10] = nonceLocal[0];
	androidResponse[11] = nonceLocal[1];

	// Nonce (Received)
	androidResponse[12] = nonceDevice[0];
	androidResponse[13] = nonceDevice[1];

	// Timestamp
	timeMillis = millis();
	androidResponse[14] = timeMillis >> 24;
	androidResponse[15] = timeMillis >> 16;
	androidResponse[16] = timeMillis >> 8;
	androidResponse[17] = timeMillis;

	// Encrypt the data
	aes256_encrypt_ecb(&ctxt, androidResponse);
	aes256_encrypt_ecb(&ctxt, androidResponse + 16);
}

// Prints the packet data sent by the mobile device that contains the
// 2FA token
void printTokenPacket() {
	Serial.print("* Token: ");
	Serial.print(androidRequest[0], HEX);
	Serial.print(androidRequest[1], HEX);
	Serial.println(androidRequest[2], HEX);

	Serial.print("* Device ID: ");
	for (uint8_t i = 3; i < 11; i++) {
		Serial.print(androidRequest[i], HEX);
	}
	Serial.println();

	Serial.print("* Node ID: ");
	Serial.print(androidRequest[11], HEX);
	Serial.println(androidRequest[12], HEX);

	Serial.print("* Nonce XOR: ");
	Serial.print(androidRequest[13], HEX);
	Serial.println(androidRequest[14], HEX);

	Serial.print("* Timestamp: ");
	Serial.print(androidRequest[15], HEX);
	Serial.print(androidRequest[16], HEX);
	Serial.print(androidRequest[17], HEX);
	Serial.println(androidRequest[18], HEX);
}

// Verifies that the token received matches the one sent by the server
// and that other packet data is also correct
void verifyTokenPacket(uint8_t serverToken[]) {
	Serial.print("Verifying...");

	// Check Node ID
	if (androidRequest[11] == nodeId[0]
		&& androidRequest[12] == nodeId[1]) {
		Serial.print("Node ID [OK] ");
	}

	else {
		Serial.println("Node IDs do not match.");
		return;
	}

	// Check Device ID

	// Check Nonces XOR
	uint8_t nonceXOR[] = { nonceLocal[0] ^ nonceDevice[0], nonceLocal[1] ^ nonceDevice[1] };
	if (androidRequest[13] == nonceXOR[0]
		&& androidRequest[14] == nonceXOR[1]) {
		Serial.print("Nonce [OK] ");
	}

	else {
		Serial.println("Nonces don't match.");
		return;
	}

	// Check token
	if (serverToken[0] == androidRequest[0]
		&& serverToken[1] == androidRequest[1]
		&& serverToken[2] == androidRequest[2]) {

		digitalWrite(dataLed, HIGH);
		Serial.println("Token [OK] ");
		Serial.println("Success!");
	}

	else {
		flashLed(errorLed, 2, 25);
		Serial.println("Error: Incorrect token.");

		return;
	}

	// Send cleared to transfer files message to device
	sendAuthClearedResponse();
}

void receiveAuthRequest() {
	xbee.readPacket();

	if (xbee.getResponse().isAvailable()) {
		// got something

		if (xbee.getResponse().getApiId() == RX_16_RESPONSE) {
			// got a rx packet
			Serial.println("Received 2FA request from mobile device:");

			xbee.getResponse().getRx16Response(rx16);
			uint8_t dataLength = rx16.getDataLength();

			for (uint8_t i = 0; i < dataLength; i++) {
				androidRequest[i] = rx16.getData(i);
			}

			// Decrypt the received data
			aes256_decrypt_ecb(&ctxt, androidRequest);
			aes256_decrypt_ecb(&ctxt, androidRequest + 16);

			// Echo received data
			printAuthRequestPacket();

			// Store the nonce received from the device
			nonceDevice[0] = androidRequest[0];
			nonceDevice[1] = androidRequest[1];

			// Respond to the auth request (encrypted)
			createAuthResponsePacket();

			// for (uint8_t i = 18; i < sizeof(androidResponse); i++) {
			// 	androidResponse[i] = androidRequest[i];
			// }

			// aes256_enc_single(key, androidResponse);

			// Transmit the response data
			sendAuthResponse();

			// TODO check option, rssi bytes
			flashLed(statusLed, 1, 10);
		}
		else {
			// not something we were expecting
			flashLed(errorLed, 2, 25);
			Serial.println("Error. Got something instead of an RX16 response.");
		}
	}
	else if (xbee.getResponse().isError()) {
		//nss.print("Error reading packet.  Error code: ");
		//nss.println(xbee.getResponse().getErrorCode());
		// or flash error led
		flashLed(errorLed, 5, 25);
		Serial.println("Error reading packet.");
	}
}

void sendAuthResponse() {
	Serial.print("Sending reply to mobile device...");
	xbee.send(txAndroidResponse);

	// flash TX indicator
	flashLed(statusLed, 1, 100);

	// after sending a tx request, we expect a status response
	// wait up to 5 seconds for the status response
	if (xbee.readPacket(5000)) {
		// got a response!

		// should be a znet tx status
		if (xbee.getResponse().getApiId() == TX_STATUS_RESPONSE) {
			xbee.getResponse().getZBTxStatusResponse(txStatus);

			// get the delivery status, the fifth byte
			if (txStatus.getStatus() == SUCCESS) {
				// success.  time to celebrate
				Serial.println("sent.");
				flashLed(statusLed, 5, 50);

				// Now wait for server to send the 2FA token
				receiveServerToken();
			}
			else {
				// the remote XBee did not receive our packet. is it powered on?
				flashLed(errorLed, 3, 500);
				Serial.println("Remote XBee did not receive our packet. Is it powered on?");
			}
		}
	}
	else if (xbee.getResponse().isError()) {
		//nss.print("Error reading packet.  Error code: ");
		//nss.println(xbee.getResponse().getErrorCode());
		// or flash error led
		flashLed(errorLed, 5, 500);
		Serial.println("Error reading packet.");
	}
	else {
		// local XBee did not provide a timely TX Status Response.  Radio is not configured properly or connected
		flashLed(errorLed, 2, 50);
		Serial.println("Error. Radio is not configured properly or not connected.");
	}
}

void receiveServerToken() {
	Serial.println("Waiting for server to send 2FA token...");
	xbee.readPacket(5000);

	if (xbee.getResponse().isAvailable()) {
		// got something, hopefully a token
		if (xbee.getResponse().getApiId() == RX_16_RESPONSE) {
			// got a rx packet
			Serial.print("Token received from server: ");
			xbee.getResponse().getRx16Response(rx16);

			// Token length should be 3 bytes (6 digits)
			uint8_t serverToken[3];
			serverToken[0] = rx16.getData(0);
			serverToken[1] = rx16.getData(1);
			serverToken[2] = rx16.getData(2);

			// Echo the hex of the token received
			Serial.print(serverToken[0], HEX);
			Serial.print(serverToken[1], HEX);
			Serial.println(serverToken[2], HEX);

			// Received 2FA token, ready to receive from Android
			receiveDeviceToken(serverToken);
		}
		else {
			// not something we were expecting
			flashLed(errorLed, 2, 25);
			Serial.println("An unexpected error occurred.");
		}
	}
	else if (xbee.getResponse().isError()) {
		//nss.print("Error reading packet.  Error code: ");
		//nss.println(xbee.getResponse().getErrorCode());
		// or flash error led
		flashLed(errorLed, 5, 25);
		Serial.println("Error reading packet.");
	}
	else {
		Serial.println("Server didn't send anything within the time frame.");
		Serial.println("Starting over from the beginning.");
	}
}

void receiveDeviceToken(uint8_t serverToken[]) {
	Serial.print("Waiting for mobile device to send token request...");
	flashLed(statusLed, 5, 25);
	// }

	// Now wait for Android to send data
	xbee.readPacket(120000);

	if (xbee.getResponse().isAvailable()) {
		// got something, hopefully the Android response
		// Token (3)
		// Device ID (8)
		// NodeId (2)
		// Nonce(android) XOR Nonce(node) (2)
		// Timestamp (4)
		if (xbee.getResponse().getApiId() == RX_16_RESPONSE) {
			Serial.println("received.");

			// got a rx packet
			xbee.getResponse().getRx16Response(rx16);
			uint8_t dataLength = rx16.getDataLength();

			for (uint8_t i = 0; i < dataLength; i++) {
				androidRequest[i] = rx16.getData(i);
			}

			// Decrypt the received data
			// aes256_dec_single(key, androidRequest);
			aes256_decrypt_ecb(&ctxt, androidRequest);
			aes256_decrypt_ecb(&ctxt, androidRequest + 16);

			// Echo the received data
			printTokenPacket();

			// Verify token
			verifyTokenPacket(serverToken);
		}
		else {
			// not something we were expecting
			flashLed(errorLed, 2, 25);
			Serial.println("Error: Not an RX_16_RESPONSE");
		}
	}
	else if (xbee.getResponse().isError()) {
		//nss.print("Error reading packet.  Error code: ");
		//nss.println(xbee.getResponse().getErrorCode());
		// or flash error led
		flashLed(errorLed, 5, 25);
		Serial.println("Error reading packet.");
	}
	else {
		Serial.println("An unexpected error occurred.");
	}
}

void sendAuthClearedResponse() {
	Serial.print("Sending 'all cleared' to mobile device...");
	// TODO create response
    androidResponse[0] = 0x00;
    androidResponse[1] = 0x00;
    androidResponse[2] = 0xFF;
    androidResponse[3] = 0xFF;
	xbee.send(txAndroidResponse);

	// after sending a tx request, we expect a status response
	// wait up to 5 seconds for the status response
	if (xbee.readPacket(5000)) {
		// got a response!

		// should be a znet tx status
		if (xbee.getResponse().getApiId() == TX_STATUS_RESPONSE) {
			xbee.getResponse().getZBTxStatusResponse(txStatus);

			// get the delivery status, the fifth byte
			if (txStatus.getStatus() == SUCCESS) {
				// success.  time to celebrate
				Serial.println("sent.");
				receiveFileData();
				flashLed(statusLed, 5, 50);
			}
			else {
				// the remote XBee did not receive our packet. is it powered on?
				Serial.println("Remote XBee did not receive our packet. Is it powered on?");
			}
		}
	}
	else if (xbee.getResponse().isError()) {
		//nss.print("Error reading packet.  Error code: ");
		//nss.println(xbee.getResponse().getErrorCode());
		// or flash error led
		flashLed(errorLed, 5, 500);
		Serial.println("Error reading packet.");
	}
	else {
		// local XBee did not provide a timely TX Status Response.  Radio is not configured properly or connected
		flashLed(errorLed, 2, 50);
		Serial.println("Error. Radio is not configured properly or not connected.");
	}
}

void receiveFileData() {
	Serial.print("Waiting for mobile device to send a file...");
	flashLed(statusLed, 5, 25);
	// }

	// Now wait for Android to send data
	xbee.readPacket(60000);

	if (xbee.getResponse().isAvailable()) {
		// got something, hopefully the Android response
		// Token (3)
		// Device ID (8)
		// NodeId (2)
		// Nonce(android) XOR Nonce(node) (2)
		// Timestamp (4)
		if (xbee.getResponse().getApiId() == RX_16_RESPONSE) {
			Serial.println("received.");

			// got a rx packet
			xbee.getResponse().getRx16Response(rx16);
			uint8_t dataLength = rx16.getDataLength();

			for (uint8_t i = 0; i < dataLength; i++) {
				androidRequest[i] = rx16.getData(i);
                                char buf[12];
				Serial.print(char(androidRequest[i]));
			}

			// Decrypt the received data
			// aes256_dec_single(key, androidRequest);
			// aes256_decrypt_ecb(&ctxt, androidRequest);
			// aes256_decrypt_ecb(&ctxt, androidRequest + 16);

			// Echo the received data
			// printTokenPacket();

			// Verify token
			// verifyTokenPacket(serverToken);
		}
		else {
			// not something we were expecting
			flashLed(errorLed, 2, 25);
			Serial.println("Error: Not an RX_16_RESPONSE");
		}
	}
	else if (xbee.getResponse().isError()) {
		//nss.print("Error reading packet.  Error code: ");
		//nss.println(xbee.getResponse().getErrorCode());
		// or flash error led
		flashLed(errorLed, 5, 25);
		Serial.println("Error reading packet.");
	}
	else {
		Serial.println("An unexpected error occurred.");
	}
}

void setup() {
	// start serial
	Serial.begin(57600);
	xbee.setSerial(Serial);

	Serial.print("Starting setup...");

	// Set the LED pins to output
	pinMode(notificationLed, OUTPUT);
	pinMode(statusLed, OUTPUT);
	pinMode(errorLed, OUTPUT);
	pinMode(dataLed,  OUTPUT);

	// Initialise AES
	aes256_init(&ctxt, key);

	// Generate a random seed
	// if analog input pin 0 is unconnected, random analog
	// noise will cause the call to randomSeed() to generate
	// different seed numbers each time the sketch runs.
	// randomSeed() will then shuffle the random function.
	randomSeed(analogRead(0));

	// Populate androidRequest with 0s
	for (uint8_t i = 0; i < sizeof(androidRequest); i++) {
		androidRequest[i] = 0;
	}

	// Populate androidResponse with 0s
	for (uint8_t i = 0; i < sizeof(androidResponse); i++) {
		androidResponse[i] = 0;
	}

	// Flash twice; setup is complete
	flashLed(notificationLed, 2, 50);
	Serial.println("done.");

	// aes256_done(&ctxt);
}

// continuously reads packets, looking for RX16
void loop() {
	// receive RX
	receiveAuthRequest();
}

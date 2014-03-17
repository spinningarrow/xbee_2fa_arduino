#include <XBee.h>

XBee xbee = XBee();
XBeeResponse response = XBeeResponse();

// create reusable response objects for responses we expect to handle
Rx16Response rx16 = Rx16Response();

int notificationLed = 10;
int statusLed = 11;
int errorLed = 12;
int dataLed = 13;
unsigned long timeMillis;

uint8_t option = 0;
uint8_t data = 0;

uint8_t key[] = {0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7};

// Received packet format:
// Nonce: 2 bytes
// IMEI: 8 bytes
// Node ID: 2 bytes
// Timestamp: 4 bytes
uint8_t androidRequest[32];
uint8_t androidResponse[32];

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
	androidResponse[10] = 0x00;
	androidResponse[11] = uint8_t(random(255));

	// Nonce (Received)
	androidResponse[12] = androidRequest[0];
	androidResponse[13] = androidRequest[1];

	// Timestamp
	timeMillis = millis();
	androidResponse[14] = timeMillis >> 24;
	androidResponse[15] = timeMillis >> 16;
	androidResponse[16] = timeMillis >> 8;
	androidResponse[17] = timeMillis;
}

// Prints the packet data sent by the mobile device that contains the
// 2FA token
void printTokenPacket() {
	Serial.print("* Token: ");
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

	Serial.print("* Nonce XOR: ");
	Serial.print(androidRequest[12], HEX);
	Serial.println(androidRequest[13], HEX);

	Serial.print("* Timestamp: ");
	Serial.print(androidRequest[14], HEX);
	Serial.print(androidRequest[15], HEX);
	Serial.print(androidRequest[16], HEX);
	Serial.println(androidRequest[17], HEX);
}

// Verifies that the token received matches the one sent by the server
// and that other packet data is also correct
void verifyTokenPacket(uint8_t serverToken[]) {
	// Check Node ID

	// Check Device ID

	// Check Nonces

	// Check token
	if (serverToken[0] == androidRequest[0]
		&& serverToken[1] == androidRequest[1]) {
		flashLed(statusLed, 20, 25);
		flashLed(errorLed, 20, 25);

		digitalWrite(dataLed, HIGH);

		delay(5000);

		digitalWrite(dataLed, LOW);

		Serial.println("Success! Token is correct.");
	}

	else {
		flashLed(statusLed, 2, 25);
		flashLed(errorLed, 2, 25);

		Serial.println("Error: Incorrect token.");
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

	// aes128_dec_single(key, aesdata2);

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
}

// continuously reads packets, looking for RX16
void loop() {

	// receive RX
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
			// aes256_dec_single(key, androidRequest);

			// Echo received data
			printAuthRequestPacket();

			// Respond to the auth request
			createAuthResponsePacket();

			// for (uint8_t i = 18; i < sizeof(androidResponse); i++) {
			// 	androidResponse[i] = androidRequest[i];
			// }

			// aes256_enc_single(key, androidResponse);

			// Transmit the response data
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
						Serial.println("Waiting for server to send 2FA token...");
						xbee.readPacket(5000);

						if (xbee.getResponse().isAvailable()) {
							// got something, hopefully a token
							if (xbee.getResponse().getApiId() == RX_16_RESPONSE) {
								// got a rx packet
								Serial.print("Token received from server: ");
								xbee.getResponse().getRx16Response(rx16);

								// Token length should be 3 bytes (6 digits)
								uint8_t* serverToken = rx16.getData();

								// Echo the hex of the token received
								Serial.print(serverToken[0], HEX);
								Serial.print(serverToken[1], HEX);
								Serial.println(serverToken[2], HEX);

								// if (msb == 0x00 && lsb == 0xFF) {
								// Received 2FA token, ready to receive from Android
								Serial.print("Waiting for mobile device to send token request...");
								flashLed(statusLed, 5, 25);
								// }

								// Now wait for Android to send data
								xbee.readPacket(120000);

								if (xbee.getResponse().isAvailable()) {
									// got something, hopefully the Android response
									// Token (2)
									// Device ID (8)
									// NodeId (2)
									// Nonce(android) (2)
									// Nonce(node) (2)
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

			delay(1000);

			// TODO check option, rssi bytes
			flashLed(statusLed, 1, 10);

			// set dataLed PWM to value of the first byte in the data
			// analogWrite(dataLed, data);
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

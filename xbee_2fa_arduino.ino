/**
 * Copyright (c) 2009 Andrew Rapp. All rights reserved.
 *
 * This file is part of XBee-Arduino.
 *
 * XBee-Arduino is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * XBee-Arduino is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with XBee-Arduino.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <XBee.h>
/*
This example is for Series 1 XBee (802.15.4)
 Receives either a RX16 or RX64 packet and sets a PWM value based on packet data.
 Error led is flashed if an unexpected packet is received
 */

XBee xbee = XBee();
XBeeResponse response = XBeeResponse();

// create reusable response objects for responses we expect to handle
Rx16Response rx16 = Rx16Response();

int notificationLed = 10;
int statusLed = 11;
int errorLed = 12;
int dataLed = 13;
long randNumber;
unsigned long timeMillis;

uint8_t option = 0;
uint8_t data = 0;

// uint8_t dataLong[] = {0, 0, 0, 0};
// uint8_t payload2[] = { 0, 0, 0, 0 };

// allocate two bytes for to hold a 10-bit analog reading
// uint8_t payload[] = { 0, 0, 0 };

uint8_t key[] = {0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7};
// uint8_t aesdata[] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5}; //16 chars == 16 bytes

// uint8_t aesdata2[] = {0x5E, 0x8C, 0x5D, 0x61, 0x3C, 0xF5, 0x00, 0x99, 0x5F, 0xB6, 0xB0, 0x3E, 0x0A, 0x8B, 0x26, 0x6D};

// Received packet format:
// Nonce: 2 bytes
// IMEI: 8 bytes
// Node ID: 2 bytes
// Timestamp: 4 bytes
uint8_t androidRequest[32];

uint8_t androidResponse[32];


// 5E 8C 5D 61 3C F5 00 99 5F B6 B0 3E 0A 8B 26 6D
// 0x5E 0x8C 0x5D 0x61 0x3C 0xF5 0x00 0x99 0x5F 0xB6 0xB0 0x3E 0x0A 0x8B 0x26 0x6D

// 16-bit addressing: Enter address of remote XBee, typically the coordinator
// Tx16Request tx = Tx16Request(0xFFFF, payload, sizeof(payload));
// Tx16Request txaes = Tx16Request(0xFFFF, aesdata2, sizeof(aesdata2));
Tx16Request txAndroidResponse = Tx16Request(0xFFFF, androidResponse, sizeof(androidResponse));
TxStatusResponse txStatus = TxStatusResponse();

// Tx16Request tx2 = Tx16Request(0xFFFF, payload2, sizeof(payload2));
TxStatusResponse txStatus2 = TxStatusResponse();

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

void setup() {
	pinMode(notificationLed, OUTPUT);
	pinMode(statusLed, OUTPUT);
	pinMode(errorLed, OUTPUT);
	pinMode(dataLed,  OUTPUT);

	// start serial
	Serial.begin(57600);
	xbee.setSerial(Serial);

	// aes128_dec_single(key, aesdata2);

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
	Serial.println("Setup complete.");
}

// continuously reads packets, looking for RX16 or RX64
void loop() {

	// receive RX
	// encrypted packet
	xbee.readPacket();

	if (xbee.getResponse().isAvailable()) {
		// got something

		if (xbee.getResponse().getApiId() == RX_16_RESPONSE) {
			// got a rx packet
			Serial.println("Received 2FA request from mobile device.");
			// TODO echo data in a structured manner

			xbee.getResponse().getRx16Response(rx16);
			uint8_t dataLength = rx16.getDataLength();

			for (uint8_t i = 0; i < dataLength; i++) {
				androidRequest[i] = rx16.getData(i);
			}

			// Decrypt the received data
			// aes256_dec_single(key, androidRequest);

			// Node ID
			androidResponse[0] = 0x00;
			androidResponse[1] = 0x01;

			// Device ID (e.g., IMEI)
			for (uint8_t i = 2; i < 10; i++) {
				androidResponse[i] = androidRequest[i];
			}

			// Nonce (Fio)
			randNumber = random(255);
			uint8_t nonceFio = uint8_t(randNumber);

			androidResponse[10] = 0x00;
			androidResponse[11] = nonceFio;

			// Nonce (Received)
			androidResponse[12] = androidRequest[0];
			androidResponse[13] = androidRequest[1];

			// Timestamp
			timeMillis = millis();
			androidResponse[14] = timeMillis >> 24;
			androidResponse[15] = timeMillis >> 16;
			androidResponse[16] = timeMillis >> 8;
			androidResponse[17] = timeMillis;

			// for (uint8_t i = 18; i < sizeof(androidResponse); i++) {
			// 	androidResponse[i] = androidRequest[i];
			// }

			// aes256_enc_single(key, androidResponse);

			// Transmit the response data
			xbee.send(txAndroidResponse);
			Serial.println("Sending reply to mobile device...");

			// flash TX indicator
			flashLed(statusLed, 1, 100);

			// after sending a tx request, we expect a status response
			// wait up to 5 seconds for the status response
			if (xbee.readPacket(5000)) {
				// got a response!

				// should be a znet tx status
				if (xbee.getResponse().getApiId() == TX_STATUS_RESPONSE) {
					xbee.getResponse().getZBTxStatusResponse(txStatus2);

					// get the delivery status, the fifth byte
					if (txStatus2.getStatus() == SUCCESS) {
						// success.  time to celebrate
						flashLed(statusLed, 5, 50);
						Serial.println("...sent.");

						// Now wait for server to send the 2FA token
						Serial.println("Waiting for server to send 2FA token...");
						xbee.readPacket(5000);

						if (xbee.getResponse().isAvailable()) {
							// got something, hopefully a token
							if (xbee.getResponse().getApiId() == RX_16_RESPONSE) {
								// got a rx packet
								Serial.print("Token received from server: ");

								xbee.getResponse().getRx16Response(rx16);
								uint8_t dataLength = rx16.getDataLength();

								uint8_t token0 = rx16.getData(0);
								uint8_t token1 = rx16.getData(1);

								Serial.print(token0);
								Serial.println(token1);

								// if (msb == 0x00 && lsb == 0xFF) {
								// Received 2FA token, ready to receive from Android
								flashLed(statusLed, 5, 25);
								flashLed(errorLed, 5, 25);
								Serial.println("Waiting for mobile device to send token request...");
								// }

								// Now wait for Android to send data
								xbee.readPacket(30000);

								if (xbee.getResponse().isAvailable()) {
									// got something, hopefully the Android response
									// Token (2)
									// Device ID (8)
									// NodeId (2)
									// Nonce(android) (2)
									// Nonce(node) (2)
									// Timestamp (4)
									if (xbee.getResponse().getApiId() == RX_16_RESPONSE) {
										Serial.println("...received.");

										// got a rx packet
										xbee.getResponse().getRx16Response(rx16);
										uint8_t dataLength = rx16.getDataLength();

										for (uint8_t i = 0; i < dataLength; i++) {
											androidRequest[i] = rx16.getData(i);
										}

										// Decrypt the received data
										// aes256_dec_single(key, androidRequest);

										// Check Node ID

										// Check Device ID

										// Check Nonces

										// Check token
										if (token0 == androidRequest[0] && token1 == androidRequest[1]) {
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

											Serial.println("Error: Incorrect correct.");
										}

										// if (msb == 0x00 && lsb == 0xFF) {
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

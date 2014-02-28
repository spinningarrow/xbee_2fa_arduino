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
#include <AESLib.h>
/*
This example is for Series 1 XBee (802.15.4)
 Receives either a RX16 or RX64 packet and sets a PWM value based on packet data.
 Error led is flashed if an unexpected packet is received
 */

XBee xbee = XBee();
XBeeResponse response = XBeeResponse();
// create reusable response objects for responses we expect to handle
Rx16Response rx16 = Rx16Response();
// Rx64Response rx64 = Rx64Response();

int notificationLed = 10;
int statusLed = 11;
int errorLed = 12;
int dataLed = 13;
long randNumber;

uint8_t option = 0;
uint8_t data = 0;

uint8_t dataLong[] = {0, 0, 0, 0};
uint8_t payload2[] = { 0, 0, 0, 0 };

// allocate two bytes for to hold a 10-bit analog reading
uint8_t payload[] = { 0, 0, 0 };

uint8_t key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
uint8_t aesdata[] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5}; //16 chars == 16 bytes

uint8_t aesdata2[] = {0x5E, 0x8C, 0x5D, 0x61, 0x3C, 0xF5, 0x00, 0x99, 0x5F, 0xB6, 0xB0, 0x3E, 0x0A, 0x8B, 0x26, 0x6D};

// 5E 8C 5D 61 3C F5 00 99 5F B6 B0 3E 0A 8B 26 6D
// 0x5E 0x8C 0x5D 0x61 0x3C 0xF5 0x00 0x99 0x5F 0xB6 0xB0 0x3E 0x0A 0x8B 0x26 0x6D

// 16-bit addressing: Enter address of remote XBee, typically the coordinator
Tx16Request tx = Tx16Request(0xFFFF, payload, sizeof(payload));
Tx16Request txaes = Tx16Request(0xFFFF, aesdata2, sizeof(aesdata2));
TxStatusResponse txStatus = TxStatusResponse();

Tx16Request tx2 = Tx16Request(0xFFFF, payload2, sizeof(payload2));
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

	aes128_dec_single(key, aesdata2);

	// if analog input pin 0 is unconnected, random analog
	// noise will cause the call to randomSeed() to generate
	// different seed numbers each time the sketch runs.
	// randomSeed() will then shuffle the random function.
	randomSeed(analogRead(0));

	// Flash twice; setup is complete
	flashLed(notificationLed, 2, 50);
}

// continuously reads packets, looking for RX16 or RX64
void loop() {

	// send TX with data
	payload[0] = 0x09; // REMOTE_ARDUINO_DATA
	payload[1] = 0x01; // LED_ON_OFF
	payload[2] = data; // data (LED state, in this case)
	// xbee.send(txaes);

	aes128_enc_single(key, aesdata);

	// flash TX indicator
	// flashLed(statusLed, 1, 100);

	// after sending a tx request, we expect a status response
	// wait up to 5 seconds for the status response
	// if (xbee.readPacket(5000)) {
	//   // got a response!

	//   // should be a znet tx status
	//   if (xbee.getResponse().getApiId() == TX_STATUS_RESPONSE) {
	//     xbee.getResponse().getZBTxStatusResponse(txStatus);

	//     // get the delivery status, the fifth byte
	//     if (txStatus.getStatus() == SUCCESS) {
	//       // success.  time to celebrate
	//       flashLed(statusLed, 5, 50);
	//     }
	//     else {
	//       // the remote XBee did not receive our packet. is it powered on?
	//       flashLed(errorLed, 3, 500);
	//     }
	//   }
	// }
	// else if (xbee.getResponse().isError()) {
	//   //nss.print("Error reading packet.  Error code: ");
	//   //nss.println(xbee.getResponse().getErrorCode());
	//   // or flash error led
	// }
	// else {
	//   // local XBee did not provide a timely TX Status Response.  Radio is not configured properly or connected
	//   flashLed(errorLed, 2, 50);
	// }

	// delay(1000);

	// receive RX
	xbee.readPacket();

	if (xbee.getResponse().isAvailable()) {
		// got something

		if (xbee.getResponse().getApiId() == RX_16_RESPONSE) {
			// got a rx packet

			// if (xbee.getResponse().getApiId() == RX_16_RESPONSE) {
				xbee.getResponse().getRx16Response(rx16);
				option = rx16.getOption();
				data = rx16.getData(0);
				dataLong[0] = rx16.getData(0);
				dataLong[1] = rx16.getData(1);
				dataLong[2] = rx16.getData(2);
				dataLong[3] = rx16.getData(3);

				payload2[0] = dataLong[3];
				payload2[1] = dataLong[2];
				payload2[2] = dataLong[1];
				payload2[3] = dataLong[0];


				// send TX with data
//        payload[0] = 0x09; // REMOTE_ARDUINO_DATA
//        payload[1] = 0x01; // LED_ON_OFF
//        payload[2] = data; // data (LED state, in this case)
				xbee.send(tx2);

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
						}
						else {
							// the remote XBee did not receive our packet. is it powered on?
							flashLed(errorLed, 3, 500);
						}
					}
				}
				else if (xbee.getResponse().isError()) {
					//nss.print("Error reading packet.  Error code: ");
					//nss.println(xbee.getResponse().getErrorCode());
					// or flash error led
					flashLed(errorLed, 5, 500);
				}
				else {
					// local XBee did not provide a timely TX Status Response.  Radio is not configured properly or connected
					flashLed(errorLed, 2, 50);
				}

				delay(1000);
			// }
			// else {
			//   xbee.getResponse().getRx64Response(rx64);
			//   option = rx64.getOption();
			//   data = rx64.getData(0);
			// }

			// TODO check option, rssi bytes
			flashLed(statusLed, 1, 10);

			// set dataLed PWM to value of the first byte in the data
			analogWrite(dataLed, data);
		}
		else {
			// not something we were expecting
			flashLed(errorLed, 2, 25);
		}
	}
	else if (xbee.getResponse().isError()) {
		//nss.print("Error reading packet.  Error code: ");
		//nss.println(xbee.getResponse().getErrorCode());
		// or flash error led
		flashLed(errorLed, 5, 25);
	}
}

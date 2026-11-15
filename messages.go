// The MIT License
//
// Copyright (c) 2019-2020, Cloudflare, Inc. and Apple, Inc. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package odoh

import (
	"encoding/binary"
	"fmt"
)

type ObliviousMessageType uint8

const (
	QueryType    ObliviousMessageType = 0x01
	ResponseType ObliviousMessageType = 0x02
)

//	struct {
//	   opaque dns_message<1..2^16-1>;
//	   opaque padding<0..2^16-1>;
//	} ObliviousDoHQueryBody;
type ObliviousDNSMessageBody struct {
	DnsMessage []byte
	Padding    []byte
}

func (m ObliviousDNSMessageBody) Marshal() []byte {
	return concat(encodeLengthPrefixedSlice(m.DnsMessage), encodeLengthPrefixedSlice(m.Padding))
}

func UnmarshalMessageBody(data []byte) (ObliviousDNSMessageBody, error) {
	if len(data) < 2 {
		return ObliviousDNSMessageBody{}, fmt.Errorf("Invalid DNS message length")
	}
	messageLength := int(binary.BigEndian.Uint16(data))
	if 2+messageLength > len(data) {
		return ObliviousDNSMessageBody{}, fmt.Errorf("Invalid DNS message length")
	}
	msg := make([]byte, messageLength)
	copy(msg, data[2:2+messageLength])

	if len(data) < 2+int(messageLength)+2 {
		return ObliviousDNSMessageBody{}, fmt.Errorf("Invalid DNS padding length")
	}
	paddingLength := int(binary.BigEndian.Uint16(data[2+messageLength:]))
	if 2+messageLength+2+paddingLength > len(data) {
		return ObliviousDNSMessageBody{}, fmt.Errorf("Invalid DNS padding length")
	}

	pad := make([]byte, paddingLength)
	copy(pad, data[2+messageLength+2:2+messageLength+2+paddingLength])
	return ObliviousDNSMessageBody{
		DnsMessage: msg,
		Padding:    pad,
	}, nil
}

func (m ObliviousDNSMessageBody) Message() []byte {
	return m.DnsMessage
}

type ObliviousDNSQuery struct {
	ObliviousDNSMessageBody
}

func CreateObliviousDNSQuery(query []byte, paddingBytes uint16) *ObliviousDNSQuery {
	q := make([]byte, len(query))
	copy(q, query)
	msg := ObliviousDNSMessageBody{
		DnsMessage: q,
		Padding:    make([]byte, int(paddingBytes)),
	}
	return &ObliviousDNSQuery{
		msg,
	}
}

func UnmarshalQueryBody(data []byte) (*ObliviousDNSQuery, error) {
	msg, err := UnmarshalMessageBody(data)
	if err != nil {
		return nil, err
	}

	return &ObliviousDNSQuery{msg}, nil
}

type ObliviousDNSResponse struct {
	ObliviousDNSMessageBody
}

func CreateObliviousDNSResponse(response []byte, paddingBytes uint16) *ObliviousDNSResponse {
	r := make([]byte, len(response))
	copy(r, response)
	msg := ObliviousDNSMessageBody{
		DnsMessage: r,
		Padding:    make([]byte, int(paddingBytes)),
	}
	return &ObliviousDNSResponse{
		msg,
	}
}

func UnmarshalResponseBody(data []byte) (*ObliviousDNSResponse, error) {
	msg, err := UnmarshalMessageBody(data)
	if err != nil {
		return nil, err
	}

	return &ObliviousDNSResponse{msg}, nil
}

//	struct {
//	   uint8  message_type;
//	   opaque key_id<0..2^16-1>;
//	   opaque encrypted_message<1..2^16-1>;
//	} ObliviousDoHMessage;
type ObliviousDNSMessage struct {
	MessageType      ObliviousMessageType
	KeyID            []byte
	EncryptedMessage []byte
}

func (m ObliviousDNSMessage) Type() ObliviousMessageType {
	return m.MessageType
}

func CreateObliviousDNSMessage(messageType ObliviousMessageType, keyID []byte, encryptedMessage []byte) *ObliviousDNSMessage {
	return &ObliviousDNSMessage{
		MessageType:      messageType,
		KeyID:            keyID,
		EncryptedMessage: encryptedMessage,
	}
}

func (m ObliviousDNSMessage) Marshal() []byte {
	encodedKey := encodeLengthPrefixedSlice(m.KeyID)
	encodedMessage := encodeLengthPrefixedSlice(m.EncryptedMessage)

	return concat([]byte{uint8(m.MessageType)}, encodedKey, encodedMessage)
}

func UnmarshalDNSMessage(data []byte) (ObliviousDNSMessage, error) {
	if len(data) < 1 {
		return ObliviousDNSMessage{}, fmt.Errorf("Invalid data length: %d", len(data))
	}

	messageType := data[0]
	keyID, messageOffset, err := decodeLengthPrefixedSlice(data[1:])
	if err != nil {
		return ObliviousDNSMessage{}, err
	}
	if 1+messageOffset > len(data) {
		return ObliviousDNSMessage{}, fmt.Errorf("Invalid data length: %d", len(data))
	}
	encryptedMessage, _, err := decodeLengthPrefixedSlice(data[1+messageOffset:])
	if err != nil {
		return ObliviousDNSMessage{}, err
	}

	return ObliviousDNSMessage{
		MessageType:      ObliviousMessageType(messageType),
		KeyID:            keyID,
		EncryptedMessage: encryptedMessage,
	}, nil
}

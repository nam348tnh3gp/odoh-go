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

// This version of odoh.go uses github.com/jedisct1/go-hpke-compact instead of
// github.com/cisco/go-hpke. Only X25519-HKDF-SHA256 is supported as the KEM and
// HKDF-SHA256 as the KDF (AEAD: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305).

package odoh

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	hpkecompact "github.com/jedisct1/go-hpke-compact"
)

type (
	KEMID  = hpkecompact.KemID
	KDFID  = hpkecompact.KdfID
	AEADID = hpkecompact.AeadID
)

const (
	ODOH_VERSION               = uint16(0x0001)
	ODOH_SECRET_LENGTH         = 32
	ODOH_PADDING_BYTE          = uint8(0)
	ODOH_LABEL_KEY_ID          = "odoh key id"
	ODOH_LABEL_KEY             = "odoh key"
	ODOH_LABEL_NONCE           = "odoh nonce"
	ODOH_LABEL_QUERY           = "odoh query"
	ODOH_LABEL_RESPONSE        = "odoh response"
	ODOH_DEFAULT_KEMID  KEMID  = hpkecompact.KemX25519HkdfSha256
	ODOH_DEFAULT_KDFID  KDFID  = hpkecompact.KdfHkdfSha256
	ODOH_DEFAULT_AEADID AEADID = hpkecompact.AeadAes128Gcm
	x25519KeySize              = 32
)

func newSuite(kemID KEMID, kdfID KDFID, aeadID AEADID) (*hpkecompact.Suite, error) {
	if aeadID == hpkecompact.AeadExportOnly {
		return nil, errors.New("export-only AEAD is not supported")
	}
	return hpkecompact.NewSuite(kemID, kdfID, aeadID)
}

// concat always returns a freshly allocated slice, so callers' backing arrays
// are never modified.
func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func responseNonceSize(suite *hpkecompact.Suite) int {
	n := int(suite.KeyBytes)
	if m := int(suite.NonceBytes); m > n {
		n = m
	}
	return n
}

type ObliviousDoHConfigContents struct {
	KemID          KEMID
	KdfID          KDFID
	AeadID         AEADID
	PublicKeyBytes []byte
}

func CreateObliviousDoHConfigContents(kemID KEMID, kdfID KDFID, aeadID AEADID, publicKeyBytes []byte) (ObliviousDoHConfigContents, error) {
	if _, err := newSuite(kemID, kdfID, aeadID); err != nil {
		return ObliviousDoHConfigContents{}, err
	}

	if len(publicKeyBytes) != x25519KeySize {
		return ObliviousDoHConfigContents{}, errors.New("invalid HPKE public key length")
	}

	pub := make([]byte, len(publicKeyBytes))
	copy(pub, publicKeyBytes)
	return ObliviousDoHConfigContents{
		KemID:          kemID,
		KdfID:          kdfID,
		AeadID:         aeadID,
		PublicKeyBytes: pub,
	}, nil
}

func (k ObliviousDoHConfigContents) KeyID() []byte {
	suite, err := newSuite(k.KemID, k.KdfID, k.AeadID)
	if err != nil {
		return nil
	}

	identifiers := make([]byte, 8)
	binary.BigEndian.PutUint16(identifiers[0:], uint16(k.KemID))
	binary.BigEndian.PutUint16(identifiers[2:], uint16(k.KdfID))
	binary.BigEndian.PutUint16(identifiers[4:], uint16(k.AeadID))
	binary.BigEndian.PutUint16(identifiers[6:], uint16(len(k.PublicKeyBytes)))
	config := concat(identifiers, k.PublicKeyBytes)

	// NOTE: go-hpke-compact's Extract takes (secret, salt), the reverse of cisco's (salt, ikm).
	prk := suite.Extract(config, nil)
	identifier, err := suite.Expand(prk, []byte(ODOH_LABEL_KEY_ID), suite.PrkBytes)
	if err != nil {
		return nil
	}

	return identifier
}

func (k ObliviousDoHConfigContents) Marshal() []byte {
	identifiers := make([]byte, 8)
	binary.BigEndian.PutUint16(identifiers[0:], uint16(k.KemID))
	binary.BigEndian.PutUint16(identifiers[2:], uint16(k.KdfID))
	binary.BigEndian.PutUint16(identifiers[4:], uint16(k.AeadID))
	binary.BigEndian.PutUint16(identifiers[6:], uint16(len(k.PublicKeyBytes)))

	return concat(identifiers, k.PublicKeyBytes)
}

func UnmarshalObliviousDoHConfigContents(buffer []byte) (ObliviousDoHConfigContents, error) {
	if len(buffer) < 8 {
		return ObliviousDoHConfigContents{}, errors.New("Invalid serialized ObliviousDoHConfigContents")
	}

	kemId := binary.BigEndian.Uint16(buffer[0:])
	kdfId := binary.BigEndian.Uint16(buffer[2:])
	aeadId := binary.BigEndian.Uint16(buffer[4:])
	publicKeyLength := binary.BigEndian.Uint16(buffer[6:])

	if len(buffer[8:]) < int(publicKeyLength) {
		return ObliviousDoHConfigContents{}, errors.New("Invalid serialized ObliviousDoHConfigContents")
	}
	if publicKeyLength != x25519KeySize {
		return ObliviousDoHConfigContents{}, errors.New("Invalid HPKE public key bytes")
	}

	publicKeyBytes := buffer[8 : 8+publicKeyLength]

	var KemID KEMID
	var KdfID KDFID
	var AeadID AEADID

	switch kemId {
	case 0x0020:
		KemID = hpkecompact.KemX25519HkdfSha256
	default:
		return ObliviousDoHConfigContents{}, fmt.Errorf("Unsupported KEMID: %04x", kemId)
	}

	switch kdfId {
	case 0x0001:
		KdfID = hpkecompact.KdfHkdfSha256
	default:
		return ObliviousDoHConfigContents{}, fmt.Errorf("Unsupported KDFID: %04x", kdfId)
	}

	switch aeadId {
	case 0x0001:
		AeadID = hpkecompact.AeadAes128Gcm
	case 0x0002:
		AeadID = hpkecompact.AeadAes256Gcm
	case 0x0003:
		AeadID = hpkecompact.AeadChaCha20Poly1305
	default:
		return ObliviousDoHConfigContents{}, fmt.Errorf("Unsupported AEADID: %04x", aeadId)
	}

	if _, err := newSuite(KemID, KdfID, AeadID); err != nil {
		return ObliviousDoHConfigContents{}, errors.New("Unsupported HPKE ciphersuite")
	}

	if len(publicKeyBytes) != x25519KeySize {
		return ObliviousDoHConfigContents{}, errors.New("Invalid HPKE public key bytes")
	}

	return ObliviousDoHConfigContents{
		KemID:          KemID,
		KdfID:          KdfID,
		AeadID:         AeadID,
		PublicKeyBytes: publicKeyBytes,
	}, nil
}

func (k ObliviousDoHConfigContents) PublicKey() []byte {
	return k.PublicKeyBytes
}

func (k ObliviousDoHConfigContents) CipherSuite() (*hpkecompact.Suite, error) {
	return newSuite(k.KemID, k.KdfID, k.AeadID)
}

type ObliviousDoHConfig struct {
	Version  uint16
	Contents ObliviousDoHConfigContents
}

func CreateObliviousDoHConfig(contents ObliviousDoHConfigContents) ObliviousDoHConfig {
	return ObliviousDoHConfig{
		Version:  ODOH_VERSION,
		Contents: contents,
	}
}

func (c ObliviousDoHConfig) Marshal() []byte {
	marshalledConfig := c.Contents.Marshal()

	buffer := make([]byte, 4)
	binary.BigEndian.PutUint16(buffer[0:], uint16(c.Version))
	binary.BigEndian.PutUint16(buffer[2:], uint16(len(marshalledConfig)))

	return concat(buffer, marshalledConfig)
}

func parseConfigHeader(buffer []byte) (uint16, uint16, error) {
	if len(buffer) < 4 {
		return uint16(0), uint16(0), errors.New("Invalid ObliviousDoHConfig encoding")
	}

	version := binary.BigEndian.Uint16(buffer[0:])
	length := binary.BigEndian.Uint16(buffer[2:])
	return version, length, nil
}

func isSupportedConfigVersion(version uint16) bool {
	return version == ODOH_VERSION
}

func UnmarshalObliviousDoHConfig(buffer []byte) (ObliviousDoHConfig, error) {
	version, length, err := parseConfigHeader(buffer)
	if err != nil {
		return ObliviousDoHConfig{}, err
	}

	if !isSupportedConfigVersion(version) {
		return ObliviousDoHConfig{}, fmt.Errorf("Unsupported version: %04x", version)
	}
	if length < 8 {
		return ObliviousDoHConfig{}, errors.New("ObliviousDoHConfig contents too short")
	}
	if len(buffer[4:]) < int(length) {
		return ObliviousDoHConfig{}, fmt.Errorf("Invalid serialized ObliviousDoHConfig, expected %v bytes, got %v", length, len(buffer[4:]))
	}

	configContents, err := UnmarshalObliviousDoHConfigContents(buffer[4:])
	if err != nil {
		return ObliviousDoHConfig{}, err
	}

	return ObliviousDoHConfig{
		Version:  version,
		Contents: configContents,
	}, nil
}

type ObliviousDoHConfigs struct {
	Configs []ObliviousDoHConfig
}

func CreateObliviousDoHConfigs(configs []ObliviousDoHConfig) ObliviousDoHConfigs {
	return ObliviousDoHConfigs{
		Configs: configs,
	}
}

func (c ObliviousDoHConfigs) Marshal() []byte {
	serializedConfigs := make([]byte, 0)
	for _, config := range c.Configs {
		serializedConfigs = append(serializedConfigs, config.Marshal()...)
	}

	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer[0:], uint16(len(serializedConfigs)))

	return concat(buffer, serializedConfigs)
}

func UnmarshalObliviousDoHConfigs(buffer []byte) (ObliviousDoHConfigs, error) {
	if len(buffer) < 2 {
		return ObliviousDoHConfigs{}, errors.New("Invalid ObliviousDoHConfigs encoding")
	}

	configs := make([]ObliviousDoHConfig, 0)
	length := binary.BigEndian.Uint16(buffer[0:])
	offset := uint16(2)

	for {
		if int(offset)+4 > len(buffer) {
			break
		}
		configVersion, configLength, err := parseConfigHeader(buffer[offset:])
		if err != nil {
			return ObliviousDoHConfigs{}, errors.New("Invalid ObliviousDoHConfigs encoding")
		}

		if int(offset)+4+int(configLength) > len(buffer) {
			break
		}

		if isSupportedConfigVersion(configVersion) {
			config, err := UnmarshalObliviousDoHConfig(buffer[offset:])
			if err == nil {
				configs = append(configs, config)
			}
		} // else skip over unsupported versions

		offset += 4 + configLength
		if offset >= 2+length {
			// Stop reading
			break
		}
	}

	return CreateObliviousDoHConfigs(configs), nil
}

type ObliviousDoHKeyPair struct {
	Config    ObliviousDoHConfig
	secretKey hpkecompact.KeyPair
	Seed      []byte
}

func CreateKeyPairFromSeed(kemID KEMID, kdfID KDFID, aeadID AEADID, ikm []byte) (ObliviousDoHKeyPair, error) {
	suite, err := newSuite(kemID, kdfID, aeadID)
	if err != nil {
		return ObliviousDoHKeyPair{}, err
	}

	kp, err := suite.DeterministicKeyPair(ikm)
	if err != nil {
		return ObliviousDoHKeyPair{}, err
	}

	configContents, err := CreateObliviousDoHConfigContents(kemID, kdfID, aeadID, kp.PublicKey)
	if err != nil {
		return ObliviousDoHKeyPair{}, err
	}

	config := CreateObliviousDoHConfig(configContents)

	seed := make([]byte, len(ikm))
	copy(seed, ikm)
	return ObliviousDoHKeyPair{
		Config:    config,
		secretKey: kp,
		Seed:      seed,
	}, nil
}

func CreateDefaultKeyPairFromSeed(seed []byte) (ObliviousDoHKeyPair, error) {
	return CreateKeyPairFromSeed(ODOH_DEFAULT_KEMID, ODOH_DEFAULT_KDFID, ODOH_DEFAULT_AEADID, seed)
}

func CreateKeyPair(kemID KEMID, kdfID KDFID, aeadID AEADID) (ObliviousDoHKeyPair, error) {
	ikm := make([]byte, x25519KeySize)
	if _, err := rand.Read(ikm); err != nil {
		return ObliviousDoHKeyPair{}, err
	}
	return CreateKeyPairFromSeed(kemID, kdfID, aeadID, ikm)
}

func CreateDefaultKeyPair() (ObliviousDoHKeyPair, error) {
	return CreateKeyPair(ODOH_DEFAULT_KEMID, ODOH_DEFAULT_KDFID, ODOH_DEFAULT_AEADID)
}

type QueryContext struct {
	query     []byte
	suite     *hpkecompact.Suite
	secret    []byte
	publicKey ObliviousDoHConfigContents
}

// responseAEAD derives the response AEAD, nonce and AAD (RFC 9230, section 6.2).
func responseAEAD(suite *hpkecompact.Suite, query, secret, responseNonce []byte) (cipher.AEAD, []byte, []byte, error) {
	if suite == nil {
		return nil, nil, nil, errors.New("nil suite")
	}
	encodedResponseNonce := encodeLengthPrefixedSlice(responseNonce)
	salt := concat(query, encodedResponseNonce)
	// NOTE: Extract takes (secret, salt) in go-hpke-compact.
	prk := suite.Extract(secret, salt)

	key, err := suite.Expand(prk, []byte(ODOH_LABEL_KEY), suite.KeyBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce, err := suite.Expand(prk, []byte(ODOH_LABEL_NONCE), suite.NonceBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	aead, err := suite.NewRawCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	aad := concat([]byte{byte(ResponseType)}, encodedResponseNonce)
	return aead, nonce, aad, nil
}

func (c QueryContext) DecryptResponse(message ObliviousDNSMessage) ([]byte, error) {
	if message.MessageType != ResponseType {
		return nil, errors.New("message is not a response")
	}
	if c.suite == nil {
		return nil, errors.New("nil query context")
	}
	size := responseNonceSize(c.suite)
	if len(message.KeyID) != size {
		return nil, fmt.Errorf("Invalid response key ID length: expected %v, got %v", size, len(message.KeyID))
	}

	aead, nonce, aad, err := responseAEAD(c.suite, c.query, c.secret, message.KeyID)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, message.EncryptedMessage, aad)
}

type ResponseContext struct {
	query  []byte
	suite  *hpkecompact.Suite
	secret []byte
}

func (c ResponseContext) encryptResponseWithNonce(response *ObliviousDNSResponse, responseNonce []byte) (ObliviousDNSMessage, error) {
	aead, nonce, aad, err := responseAEAD(c.suite, c.query, c.secret, responseNonce)
	if err != nil {
		return ObliviousDNSMessage{}, err
	}

	ciphertext := aead.Seal(nil, nonce, response.Marshal(), aad)

	odohMessage := ObliviousDNSMessage{
		KeyID:            responseNonce,
		MessageType:      ResponseType,
		EncryptedMessage: ciphertext,
	}

	return odohMessage, nil
}

func (c ResponseContext) EncryptResponse(response *ObliviousDNSResponse) (ObliviousDNSMessage, error) {
	if c.suite == nil {
		return ObliviousDNSMessage{}, errors.New("nil response context")
	}
	if response == nil {
		return ObliviousDNSMessage{}, errors.New("nil response")
	}
	size := responseNonceSize(c.suite)

	responseNonce := make([]byte, size)
	read, err := rand.Read(responseNonce)
	if err != nil {
		return ObliviousDNSMessage{}, err
	}
	if read != size {
		return ObliviousDNSMessage{}, fmt.Errorf("Failed to read %v bytes", size)
	}

	return c.encryptResponseWithNonce(response, responseNonce)
}

func queryAAD(keyID []byte) []byte {
	keyIDLength := make([]byte, 2)
	binary.BigEndian.PutUint16(keyIDLength, uint16(len(keyID)))
	return concat([]byte{byte(QueryType)}, keyIDLength, keyID)
}

func (targetKey ObliviousDoHConfigContents) EncryptQuery(query *ObliviousDNSQuery) (ObliviousDNSMessage, QueryContext, error) {
	if query == nil {
		return ObliviousDNSMessage{}, QueryContext{}, errors.New("nil query")
	}
	suite, err := newSuite(targetKey.KemID, targetKey.KdfID, targetKey.AeadID)
	if err != nil {
		return ObliviousDNSMessage{}, QueryContext{}, err
	}

	if len(targetKey.PublicKeyBytes) != x25519KeySize {
		return ObliviousDNSMessage{}, QueryContext{}, errors.New("invalid HPKE public key length")
	}

	ctxI, enc, err := suite.NewClientContext(targetKey.PublicKeyBytes, []byte(ODOH_LABEL_QUERY), nil)
	if err != nil {
		return ObliviousDNSMessage{}, QueryContext{}, err
	}

	secret, err := ctxI.Export([]byte(ODOH_LABEL_RESPONSE), suite.KeyBytes)
	if err != nil {
		return ObliviousDNSMessage{}, QueryContext{}, err
	}

	keyID := targetKey.KeyID()
	aad := queryAAD(keyID)

	encodedMessage := query.Marshal()
	ct, err := ctxI.EncryptToServer(encodedMessage, aad)
	if err != nil {
		return ObliviousDNSMessage{}, QueryContext{}, err
	}

	return ObliviousDNSMessage{
		KeyID:            keyID,
		MessageType:      QueryType,
		EncryptedMessage: concat(enc, ct),
	}, QueryContext{
		secret:    secret,
		suite:     suite,
		query:     encodedMessage,
		publicKey: targetKey,
	}, nil
}

func validateMessagePadding(padding []byte) bool {
	validPadding := 1
	for _, v := range padding {
		validPadding &= subtle.ConstantTimeByteEq(v, ODOH_PADDING_BYTE)
	}
	return validPadding == 1
}

func (privateKey ObliviousDoHKeyPair) DecryptQuery(message ObliviousDNSMessage) (*ObliviousDNSQuery, ResponseContext, error) {
	if message.MessageType != QueryType {
		return nil, ResponseContext{}, errors.New("message is not a query")
	}

	suite, err := newSuite(privateKey.Config.Contents.KemID, privateKey.Config.Contents.KdfID, privateKey.Config.Contents.AeadID)
	if err != nil {
		return nil, ResponseContext{}, err
	}

	if len(message.EncryptedMessage) <= x25519KeySize+16 {
		return nil, ResponseContext{}, errors.New("encrypted message too short")
	}

	// IMPORTANT: copy enc into its own slice. go-hpke-compact's decap does
	// append(enc, serverPublicKey...); if enc were a sub-slice of
	// message.EncryptedMessage, that append would overwrite the start of the
	// ciphertext that follows it and decryption would always fail.
	enc := append([]byte(nil), message.EncryptedMessage[:x25519KeySize]...)
	ct := message.EncryptedMessage[x25519KeySize:]

	ctxR, err := suite.NewServerContext(enc, privateKey.secretKey, []byte(ODOH_LABEL_QUERY), nil)
	if err != nil {
		return nil, ResponseContext{}, err
	}

	secret, err := ctxR.Export([]byte(ODOH_LABEL_RESPONSE), suite.KeyBytes)
	if err != nil {
		return nil, ResponseContext{}, err
	}

	aad := queryAAD(privateKey.Config.Contents.KeyID())

	dnsMessage, err := ctxR.DecryptFromClient(ct, aad)
	if err != nil {
		return nil, ResponseContext{}, err
	}

	query, err := UnmarshalQueryBody(dnsMessage)
	if err != nil {
		return nil, ResponseContext{}, err
	}

	if !validateMessagePadding(query.Padding) {
		return nil, ResponseContext{}, errors.New("invalid padding")
	}

	responseContext := ResponseContext{
		suite:  suite,
		query:  query.Marshal(),
		secret: secret,
	}

	return query, responseContext, nil
}

func SealQuery(dnsQuery []byte, publicKey ObliviousDoHConfigContents) (ObliviousDNSMessage, QueryContext, error) {
	odohQuery := CreateObliviousDNSQuery(dnsQuery, 0)

	odohMessage, queryContext, err := publicKey.EncryptQuery(odohQuery)
	if err != nil {
		return ObliviousDNSMessage{}, QueryContext{}, err
	}

	return odohMessage, queryContext, nil
}

func (c QueryContext) OpenAnswer(message ObliviousDNSMessage) ([]byte, error) {
	if message.MessageType != ResponseType {
		return nil, errors.New("message is not a response")
	}
	if len(message.EncryptedMessage) == 0 {
		return nil, errors.New("empty encrypted response")
	}

	decryptedResponseBytes, err := c.DecryptResponse(message)
	if err != nil {
		return nil, errors.New("unable to decrypt the obtained response using the symmetric key sent")
	}

	decryptedResponse, err := UnmarshalResponseBody(decryptedResponseBytes)
	if err != nil {
		return nil, err
	}

	return decryptedResponse.DnsMessage, nil
}

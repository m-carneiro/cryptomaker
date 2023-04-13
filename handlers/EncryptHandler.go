package handlers

import (
	"criptomaker/services/privateKeyMaker"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
)

const (
	KeyGenerationFailedMessage   = "Key Generation Failed"
	EncryptionFailedMessage      = "EncryptionType failed"
	ContentTypeHeader            = "Content-Type"
	ApplicationJSONValue         = "application/json"
	UnsupportedEncryptionMessage = "unsupported EncryptionType Type"
	MethodNotAllowedMessage      = "Method not allowed"
)

type EncryptRequest struct {
	Message        string `json:"message"`
	EncryptionType string `json:"encryption_type"`
}

func validateRequest(request *EncryptRequest) error {
	if request.Message == "" {
		return errors.New("message field is empty or missing")
	}

	if request.EncryptionType == "" {
		return errors.New("encryption_type field is empty or missing")
	}

	supportedEncryptionTypes := []string{"RSA", "AES"}
	found := false

	for _, encryptionType := range supportedEncryptionTypes {
		if request.EncryptionType == encryptionType {
			found = true
			break
		}
	}

	if !found {
		return errors.New(UnsupportedEncryptionMessage)
	}

	return nil
}

func EncryptHandler(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(responseWriter, MethodNotAllowedMessage, http.StatusMethodNotAllowed)
		return
	}

	var requestData EncryptRequest

	err := json.NewDecoder(request.Body).Decode(&requestData)
	if err != nil {
		http.Error(responseWriter, KeyGenerationFailedMessage, http.StatusBadRequest)
		return
	}

	err = validateRequest(&requestData)
	if err != nil {
		http.Error(responseWriter, err.Error(), http.StatusBadRequest)
	}

	var encryptedMessage []byte
	var encryptedMessageBase64 string

	switch requestData.EncryptionType {
	case "RSA":
		privateKey, err := privateKeyMaker.GeneratePrivateKey(2048)
		if err != nil {
			http.Error(responseWriter, KeyGenerationFailedMessage, http.StatusInternalServerError)
			return
		}
		publicKey := &privateKey.PublicKey

		encryptedMessage, err = privateKeyMaker.EncryptWithPublicKey([]byte(requestData.Message), publicKey)
		if err != nil {
			http.Error(responseWriter, EncryptionFailedMessage, http.StatusInternalServerError)
			return
		}

		encryptedMessageBase64 = base64.StdEncoding.EncodeToString(encryptedMessage)
	case "AES":
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			http.Error(responseWriter, KeyGenerationFailedMessage, http.StatusInternalServerError)
			return
		}

		encryptedMessage, err = privateKeyMaker.EncryptWithAES([]byte(requestData.Message), key)
		if err != nil {
			http.Error(responseWriter, EncryptionFailedMessage, http.StatusInternalServerError)
			return
		}

		encryptedMessageBase64 = base64.StdEncoding.EncodeToString(encryptedMessage)

	default:
		http.Error(responseWriter, UnsupportedEncryptionMessage, http.StatusBadRequest)
		return
	}

	responseWriter.Header().Set(ContentTypeHeader, ApplicationJSONValue)
	json.NewEncoder(responseWriter).Encode(map[string]string{
		"encrypted_message": encryptedMessageBase64,
	})
	if err != nil {
		return
	}

}

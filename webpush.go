package webpush

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/hkdf"
)

const MaxRecordSize uint32 = 4096

var ErrMaxPadExceeded = errors.New("payload has exceeded the maximum length")

// saltFunc generates a salt of 16 bytes
var saltFunc = func() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return salt, err
	}

	return salt, nil
}

// HTTPClient is an interface for sending the notification HTTP request / testing
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Options are config and extra params needed to send a notification
type Options struct {
	HTTPClient      HTTPClient // Will replace with *http.Client by default if not included
	RecordSize      uint32     // Limit the record size
	Subscriber      string     // Sub in VAPID JWT token
	Topic           string     // Set the Topic header to collapse a pending messages (Optional)
	TTL             int        // Set the TTL on the endpoint POST request
	Urgency         Urgency    // Set the Urgency header to change a message priority (Optional)
	VAPIDPublicKey  string     // VAPID public key, passed in VAPID Authorization header
	VAPIDPrivateKey string     // VAPID private key, used to sign VAPID JWT token
}

// Keys are the base64 encoded values from PushSubscription.getKey()
type Keys struct {
	Auth   string `json:"auth"`
	P256dh string `json:"p256dh"`
}

// Subscription represents a PushSubscription object from the Push API
type Subscription struct {
	Endpoint string `json:"endpoint"`
	Keys     Keys   `json:"keys"`
}

// Subscription represents a PushSubscription object from the Push API
type Web struct {
	sub     Subscription
	opts    Options
	once    sync.Once
	err     error
	encrypt func(message []byte) (*http.Request, error)
	jwt     struct {
		token     *jwt.Token
		str       string
		publicKey string
		gen       func() (*jwt.Token, string, error)
	}
}

func (s *Web) token() (string, error) {
	if err := s.jwt.token.Claims.Valid(); err != nil {
		tok, str, err := s.jwt.gen()
		if err != nil {
			return "", err
		}
		s.jwt.token = tok
		s.jwt.str = str
		return str, err
	}
	return s.jwt.str, nil
}

func New(sub Subscription, opts Options) *Web {
	return &Web{sub: sub, opts: opts}
}

func (s *Web) init() {
	s.initAuth()
	if s.err != nil {
		return
	}

	// Authentication secret (auth_secret)
	authSecret, err := decodeSubscriptionKey(s.sub.Keys.Auth)
	if err != nil {
		s.err = err
		return
	}

	// dh (Diffie Hellman)
	dh, err := decodeSubscriptionKey(s.sub.Keys.P256dh)
	if err != nil {
		s.err = err
		return
	}

	// Generate 16 byte salt
	salt, err := saltFunc()
	if err != nil {
		s.err = err
		return
	}

	// Create the ecdh_secret shared key pair
	curve := elliptic.P256()

	// Application server key pairs (single use)
	localPrivateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		s.err = err
		return
	}

	localPublicKey := elliptic.Marshal(curve, x, y)

	// Combine application keys with dh
	sharedX, sharedY := elliptic.Unmarshal(curve, dh)
	if sharedX == nil {
		s.err = errors.New("Unmarshal Error: Public key is not a valid point on the curve")
		return
	}

	sx, _ := curve.ScalarMult(sharedX, sharedY, localPrivateKey)
	sharedECDHSecret := sx.Bytes()

	hash := sha256.New

	// ikm
	prkInfoBuf := bytes.NewBuffer([]byte("WebPush: info\x00"))
	prkInfoBuf.Write(dh)
	prkInfoBuf.Write(localPublicKey)

	prkHKDF := hkdf.New(hash, sharedECDHSecret, authSecret, prkInfoBuf.Bytes())
	ikm, err := getHKDFKey(prkHKDF, 32)
	if err != nil {
		s.err = err
		return
	}

	// Derive Content Encryption Key
	contentEncryptionKeyInfo := []byte("Content-Encoding: aes128gcm\x00")
	contentHKDF := hkdf.New(hash, ikm, salt, contentEncryptionKeyInfo)
	contentEncryptionKey, err := getHKDFKey(contentHKDF, 16)
	if err != nil {
		s.err = err
		return
	}

	// Derive the Nonce
	nonceInfo := []byte("Content-Encoding: nonce\x00")
	nonceHKDF := hkdf.New(hash, ikm, salt, nonceInfo)
	nonce, err := getHKDFKey(nonceHKDF, 12)
	if err != nil {
		s.err = err
		return
	}

	// Cipher
	c, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		s.err = err
		return
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		s.err = err
		return
	}
	s.encrypt = func(message []byte) (*http.Request, error) {
		// Get the record size
		recordSize := s.opts.RecordSize
		if recordSize == 0 {
			recordSize = MaxRecordSize
		}

		recordLength := int(recordSize) - 16

		// Encryption Content-Coding Header
		recordBuf := bytes.NewBuffer(salt)
		rs := make([]byte, 4)
		binary.BigEndian.PutUint32(rs, recordSize)
		recordBuf.Write(rs)
		recordBuf.Write([]byte{byte(len(localPublicKey))})
		recordBuf.Write(localPublicKey)
		// Data
		dataBuf := bytes.NewBuffer(message)

		// Pad content to max record size - 16 - header
		// Padding ending delimeter
		dataBuf.Write([]byte("\x02"))
		if err := pad(dataBuf, recordLength-recordBuf.Len()); err != nil {
			return nil, err
		}
		// Compose the ciphertext
		ciphertext := gcm.Seal([]byte{}, nonce, dataBuf.Bytes(), nil)
		recordBuf.Write(ciphertext)
		// POST request
		req, err := http.NewRequest("POST", s.sub.Endpoint, recordBuf)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Encoding", "aes128gcm")
		req.Header.Set("Content-Length", strconv.Itoa(len(ciphertext)))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("TTL", strconv.Itoa(s.opts.TTL))
		// Сheck the optional headers
		if len(s.opts.Topic) > 0 {
			req.Header.Set("Topic", s.opts.Topic)
		}

		if isValidUrgency(s.opts.Urgency) {
			req.Header.Set("Urgency", string(s.opts.Urgency))
		}
		// Get VAPID Authorization header
		vapidAuthHeader, err := s.tokenHeader()
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", vapidAuthHeader)
		return req, nil
	}
}

func (s *Web) initAuth() {
	// Create the JWT token
	subURL, err := url.Parse(s.sub.Endpoint)
	if err != nil {
		s.err = err
		return
	}
	// Decode the VAPID private key
	decodedVapidPrivateKey, err := decodeVapidKey(s.opts.VAPIDPrivateKey)
	if err != nil {
		s.err = err
		return
	}
	privKey := generateVAPIDHeaderKeys(decodedVapidPrivateKey)
	// Decode the VAPID public key
	pubKey, err := decodeVapidKey(s.opts.VAPIDPublicKey)
	if err != nil {
		s.err = err
		return
	}
	s.jwt.publicKey = base64.RawURLEncoding.EncodeToString(pubKey)
	s.jwt.gen = func() (*jwt.Token, string, error) {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.StandardClaims{
			Audience:  fmt.Sprintf("%s://%s", subURL.Scheme, subURL.Host),
			ExpiresAt: time.Now().Add(time.Hour * 12).Unix(),
			Subject:   fmt.Sprintf("mailto:%s", s.opts.Subscriber),
		})
		// Sign token with private key
		jwtString, err := token.SignedString(privKey)
		if err != nil {
			return nil, "", err
		}
		return token, jwtString, nil
	}
}

func (s *Web) tokenHeader() (string, error) {
	_, str, err := s.jwt.gen()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"vapid t=%s, k=%s",
		str,
		s.jwt.publicKey,
	), nil
}

func (s *Web) Encrypt(message []byte, options Options) (*http.Request, error) {
	s.once.Do(s.init)
	if s.err != nil {
		return nil, s.err
	}
	return s.encrypt(message)
}

// SendNotification sends a push notification to a subscription's endpoint
// Message Encryption for Web Push, and VAPID protocols.
// FOR MORE INFORMATION SEE RFC8291: https://datatracker.ietf.org/doc/rfc8291
func SendNotification(message []byte, s Subscription, options Options) (*http.Response, error) {
	req, err := New(s, options).Encrypt(message, options)
	if err != nil {
		return nil, err
	}
	if options.HTTPClient != nil {
		return options.HTTPClient.Do(req)
	}
	return http.DefaultClient.Do(req)
}

// decodeSubscriptionKey decodes a base64 subscription key.
// if necessary, add "=" padding to the key for URL decode
func decodeSubscriptionKey(key string) ([]byte, error) {
	// "=" padding
	buf := bytes.NewBufferString(key)
	if rem := len(key) % 4; rem != 0 {
		buf.WriteString(strings.Repeat("=", 4-rem))
	}

	bytes, err := base64.StdEncoding.DecodeString(buf.String())
	if err == nil {
		return bytes, nil
	}

	return base64.URLEncoding.DecodeString(buf.String())
}

// Returns a key of length "length" given an hkdf function
func getHKDFKey(hkdf io.Reader, length int) ([]byte, error) {
	key := make([]byte, length)
	n, err := io.ReadFull(hkdf, key)
	if n != len(key) || err != nil {
		return key, err
	}

	return key, nil
}

func pad(payload *bytes.Buffer, maxPadLen int) error {
	payloadLen := payload.Len()
	if payloadLen > maxPadLen {
		return ErrMaxPadExceeded
	}

	padLen := maxPadLen - payloadLen

	padding := make([]byte, padLen)
	payload.Write(padding)

	return nil
}

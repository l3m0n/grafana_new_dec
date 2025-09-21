package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	_ "modernc.org/sqlite"
)

const (
	// Matches Grafana's encryption.SaltLength
	saltLength = 8

	algDelimiter = '*' // encryptionAlgorithmDelimiter in Grafana
	envDelimiter = '#' // keyIdDelimiter in SecretsService

	algAESCFB = "aes-cfb"
	algAESGCM = "aes-gcm"
)

type dataKeyRecord struct {
	ID            string
	Provider      string
	EncryptedData []byte
}

type dsRow struct {
	ID              int64
	Name            string
	SecureJSONData  sql.NullString
}

type pluginRow struct {
	ID              int64
	OrgID           int64
	PluginID        string
	SecureJSONData  sql.NullString
}

type outputDS struct {
	ID        int64             `json:"id"`
	Name      string            `json:"name"`
	Decrypted map[string]string `json:"decrypted"`
}

type outputPlugin struct {
	ID        int64             `json:"id"`
	OrgID     int64             `json:"org_id"`
	PluginID  string            `json:"plugin_id"`
	Decrypted map[string]string `json:"decrypted"`
}

type result struct {
	DataSource    []outputDS     `json:"data_source,omitempty"`
	PluginSetting []outputPlugin `json:"plugin_setting,omitempty"`
}

type dekCacheEntry struct {
	key []byte
}

type dekCache struct {
	m map[string]dekCacheEntry
}

func newDEKCache() *dekCache {
	return &dekCache{m: make(map[string]dekCacheEntry)}
}

func (c *dekCache) get(id string) ([]byte, bool) {
	if v, ok := c.m[id]; ok {
		return v.key, true
	}
	return nil, false
}

func (c *dekCache) set(id string, key []byte) {
	c.m[id] = dekCacheEntry{key: key}
}

func main() {
	var (
		dbPath  string
		secret  string
		table   string
		output  string
	)
	flag.StringVar(&dbPath, "db", "grafana.db", "Path to grafana SQLite database file (grafana.db)")
	flag.StringVar(&secret, "secret", "SW2YcwTIb9zpOOhoPsMm", "Grafana security.secret_key used to derive keys")
	flag.StringVar(&table, "table", "all", "Which table to process: all|data_source|plugin_setting")
	flag.StringVar(&output, "output", "json", "Output format: json|text")
	flag.Parse()

	if _, err := os.Stat(dbPath); err != nil {
		log.Fatalf("DB not found: %s, err=%v", dbPath, err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Prepare DEK cache for envelope
	cache := newDEKCache()

	res := result{}

	// data_source.secure_json_data
	if table == "all" || table == "data_source" {
		dsr, err := readDataSource(ctx, db)
		if err != nil {
			log.Fatalf("read data_source: %v", err)
		}
		for _, r := range dsr {
			if !r.SecureJSONData.Valid || strings.TrimSpace(r.SecureJSONData.String) == "" {
				continue
			}
			plainMap, err := decryptSecureJSON(r.SecureJSONData.String, secret, db, cache)
			if err != nil {
				log.Printf("WARN data_source id=%d name=%q decrypt failed: %v", r.ID, r.Name, err)
				continue
			}
			res.DataSource = append(res.DataSource, outputDS{
				ID:        r.ID,
				Name:      r.Name,
				Decrypted: plainMap,
			})
		}
	}

	// plugin_setting.secure_json_data
	if table == "all" || table == "plugin_setting" {
		pr, err := readPluginSetting(ctx, db)
		if err != nil {
			log.Fatalf("read plugin_setting: %v", err)
		}
		for _, r := range pr {
			if !r.SecureJSONData.Valid || strings.TrimSpace(r.SecureJSONData.String) == "" {
				continue
			}
			plainMap, err := decryptSecureJSON(r.SecureJSONData.String, secret, db, cache)
			if err != nil {
				log.Printf("WARN plugin_setting id=%d org_id=%d plugin_id=%q decrypt failed: %v", r.ID, r.OrgID, r.PluginID, err)
				continue
			}
			res.PluginSetting = append(res.PluginSetting, outputPlugin{
				ID:        r.ID,
				OrgID:     r.OrgID,
				PluginID:  r.PluginID,
				Decrypted: plainMap,
			})
		}
	}

	switch output {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			log.Fatalf("encode json: %v", err)
		}
	case "text":
		printText(res)
	default:
		log.Fatalf("unknown output: %s", output)
	}
}

func printText(res result) {
	for _, r := range res.DataSource {
		fmt.Printf("[data_source] id=%d name=%s\n", r.ID, r.Name)
		for k, v := range r.Decrypted {
			fmt.Printf("  %s = %s\n", k, v)
		}
	}
	for _, r := range res.PluginSetting {
		fmt.Printf("[plugin_setting] id=%d org_id=%d plugin_id=%s\n", r.ID, r.OrgID, r.PluginID)
		for k, v := range r.Decrypted {
			fmt.Printf("  %s = %s\n", k, v)
		}
	}
}

// decryptSecureJSON parses secure_json_data JSON and decrypts each key/value.
func decryptSecureJSON(jsonText string, appSecret string, db *sql.DB, cache *dekCache) (map[string]string, error) {
	// In Grafana, this JSON object has values encoded as base64 (JSON []byte)
	// e.g. {"password":"BASE64..."} which unmarshal to []byte
	var encMap map[string][]byte
	if err := json.Unmarshal([]byte(jsonText), &encMap); err != nil {
		return nil, fmt.Errorf("unmarshal secure_json_data: %w", err)
	}
	out := make(map[string]string, len(encMap))
	for k, encVal := range encMap {
		plain, err := decryptPossiblyEnveloped(encVal, appSecret, db, cache)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", k, err)
		}
		out[k] = string(plain)
	}
	return out, nil
}

// decryptPossiblyEnveloped detects envelope ("#...#") and decrypts accordingly.
func decryptPossiblyEnveloped(payload []byte, appSecret string, db *sql.DB, cache *dekCache) ([]byte, error) {
	if len(payload) == 0 {
		return []byte{}, nil
	}
	if payload[0] != envDelimiter {
		// Legacy secret: decrypt with app secret directly.
		return decryptWithSecret(payload, appSecret)
	}

	// Envelope format: "#"+base64(keyID)+"#" + inner_ciphertext
	blob := payload[1:]
	i := bytes.IndexByte(blob, envDelimiter)
	if i == -1 {
		return nil, fmt.Errorf("envelope: missing closing delimiter")
	}
	b64id := blob[:i]
	inner := blob[i+1:]

	id := make([]byte, base64.RawStdEncoding.DecodedLen(len(b64id)))
	n, err := base64.RawStdEncoding.Decode(id, b64id)
	if err != nil {
		return nil, fmt.Errorf("envelope: decode key id: %w", err)
	}
	keyID := string(id[:n])

	// Resolve DEK
	dek, err := getDEK(db, keyID, appSecret, cache)
	if err != nil {
		return nil, fmt.Errorf("envelope: fetch DEK: %w", err)
	}

	// Inner ciphertext is Grafana encryption payload (with alg prefix or legacy)
	return decryptWithSecret(inner, string(dek))
}

// getDEK fetches and decrypts the data encryption key by id, using appSecret.
// Uses in-memory cache to avoid repeated DB lookups.
func getDEK(db *sql.DB, id string, appSecret string, cache *dekCache) ([]byte, error) {
	if v, ok := cache.get(id); ok {
		return v, nil
	}

	row := db.QueryRow(`SELECT name, provider, encrypted_data FROM data_keys WHERE name = ? LIMIT 1`, id)
	var rec dataKeyRecord
	if err := row.Scan(&rec.ID, &rec.Provider, &rec.EncryptedData); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("DEK not found: %s", id)
		}
		return nil, fmt.Errorf("scan data_keys: %w", err)
	}

	// For provider secretKey.v1, the key material (rec.EncryptedData) is encrypted with app secret.
	dek, err := decryptWithSecret(rec.EncryptedData, appSecret)
	if err != nil {
		return nil, fmt.Errorf("decrypt DEK with app secret: %w", err)
	}

	cache.set(id, dek)
	return dek, nil
}

// decryptWithSecret reproduces Grafana encryption.Internal.Decrypt
// - Optional algorithm prefix: "*" + base64(algorithm) + "*" + payload
// - Payload for AES-CFB:  salt(8) | iv(16) | ciphertext
// - Payload for AES-GCM:  salt(8) | nonce(12) | ciphertext+tag
func decryptWithSecret(payload []byte, secret string) ([]byte, error) {
	algorithm, toDecrypt, err := deriveAlgorithm(payload)
	if err != nil {
		return nil, err
	}
	switch algorithm {
	case algAESGCM:
		return decryptAESGCM(toDecrypt, secret)
	case algAESCFB:
		return decryptAESCFB(toDecrypt, secret)
	default:
		// Fallback to aes-cfb if unknown (match legacy behavior)
		return decryptAESCFB(toDecrypt, secret)
	}
}

// deriveAlgorithm parses optional Grafana metadata prefix.
func deriveAlgorithm(payload []byte) (string, []byte, error) {
	if len(payload) == 0 {
		return "", nil, fmt.Errorf("empty payload")
	}
	if payload[0] != algDelimiter {
		// Backwards compatible: default to aes-cfb
		return algAESCFB, payload, nil
	}
	p := payload[1:]
	idx := bytes.IndexByte(p, algDelimiter)
	if idx == -1 {
		// Corrupted metadata; fallback to aes-cfb
		return algAESCFB, p, nil
	}
	algB64 := p[:idx]
	rest := p[idx+1:]

	algBuf := make([]byte, base64.RawStdEncoding.DecodedLen(len(algB64)))
	n, err := base64.RawStdEncoding.Decode(algBuf, algB64)
	if err != nil {
		return "", nil, fmt.Errorf("decode algorithm: %w", err)
	}
	alg := string(algBuf[:n])
	if alg == "" {
		// Legacy bug compatibility
		return algAESCFB, rest, nil
	}
	return alg, rest, nil
}

// KeyToBytes is compatible with pkg/services/encryption/encryption.go
func keyToBytes(secret, salt string) []byte {
	return pbkdf2.Key([]byte(secret), []byte(salt), 10000, 32, sha256.New)
}

func decryptAESCFB(payload []byte, secret string) ([]byte, error) {
	if len(payload) < saltLength+aes.BlockSize {
		return nil, fmt.Errorf("payload too short for CFB")
	}
	salt := payload[:saltLength]
	iv := payload[saltLength : saltLength+aes.BlockSize]
	ciphertext := payload[saltLength+aes.BlockSize:]

	key := keyToBytes(secret, string(salt))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	out := make([]byte, len(ciphertext))
	stream.XORKeyStream(out, ciphertext)
	return out, nil
}

func decryptAESGCM(payload []byte, secret string) ([]byte, error) {
	if len(payload) < saltLength {
		return nil, fmt.Errorf("payload too short for GCM")
	}
	salt := payload[:saltLength]
	key := keyToBytes(secret, string(salt))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	if len(payload) < saltLength+gcm.NonceSize() {
		return nil, fmt.Errorf("payload too short for GCM nonce")
	}
	nonce := payload[saltLength : saltLength+gcm.NonceSize()]
	ciphertext := payload[saltLength+gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return plain, nil
}

func readDataSource(ctx context.Context, db *sql.DB) ([]dsRow, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, name, secure_json_data
		FROM data_source
		WHERE secure_json_data IS NOT NULL AND secure_json_data != ''
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []dsRow
	for rows.Next() {
		var r dsRow
		if err := rows.Scan(&r.ID, &r.Name, &r.SecureJSONData); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func readPluginSetting(ctx context.Context, db *sql.DB) ([]pluginRow, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, org_id, plugin_id, secure_json_data
		FROM plugin_setting
		WHERE secure_json_data IS NOT NULL AND secure_json_data != ''
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []pluginRow
	for rows.Next() {
		var r pluginRow
		if err := rows.Scan(&r.ID, &r.OrgID, &r.PluginID, &r.SecureJSONData); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

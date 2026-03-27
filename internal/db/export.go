package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

const (
	exportFormatName    = "gobastion-dbexport"
	exportFormatVersion = 1
)

var (
	uuidType      = reflect.TypeOf(uuid.UUID{})
	timeType      = reflect.TypeOf(time.Time{})
	deletedAtType = reflect.TypeOf(gorm.DeletedAt{})
)

type exportEnvelope struct {
	Format  string            `json:"format"`
	Version int               `json:"version"`
	Cipher  string            `json:"cipher"`
	KDF     exportKDFEnvelope `json:"kdf"`
	Nonce   string            `json:"nonce"`
	Payload string            `json:"payload"`
}

type exportKDFEnvelope struct {
	Name    string `json:"name"`
	Salt    string `json:"salt,omitempty"`
	Time    uint32 `json:"time,omitempty"`
	Memory  uint32 `json:"memory,omitempty"`
	Threads uint8  `json:"threads,omitempty"`
	KeyLen  uint32 `json:"key_len,omitempty"`
}

type exportPayload struct {
	Version      int           `json:"version"`
	GeneratedAt  string        `json:"generated_at"`
	SourceDriver string        `json:"source_driver"`
	Tables       []exportTable `json:"tables"`
}

type exportTable struct {
	Name string                   `json:"name"`
	Rows []map[string]encodedCell `json:"rows"`
}

type encodedCell struct {
	Type  string `json:"type"`
	Value any    `json:"value,omitempty"`
}

func getExportSecretFromEnv() (string, error) {
	secret := strings.TrimSpace(os.Getenv("DB_EXPORT_KEY"))
	if secret == "" {
		return "", fmt.Errorf("DB_EXPORT_KEY must be set")
	}
	return secret, nil
}

func tryDirectAESKey(secret string) ([]byte, bool) {
	if decoded, err := base64.StdEncoding.DecodeString(secret); err == nil {
		if isValidAESKeyLength(len(decoded)) {
			return decoded, true
		}
	}

	raw := []byte(secret)
	if isValidAESKeyLength(len(raw)) {
		return raw, true
	}

	return nil, false
}

func isValidAESKeyLength(n int) bool {
	return n == 16 || n == 24 || n == 32
}

func deriveKeyForExport(secret string) ([]byte, exportKDFEnvelope, error) {
	if raw, ok := tryDirectAESKey(secret); ok {
		return raw, exportKDFEnvelope{Name: "direct"}, nil
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, exportKDFEnvelope{}, fmt.Errorf("generate salt: %w", err)
	}

	kdf := exportKDFEnvelope{
		Name:    "argon2id",
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Time:    3,
		Memory:  64 * 1024,
		Threads: 2,
		KeyLen:  32,
	}

	key := argon2.IDKey([]byte(secret), salt, kdf.Time, kdf.Memory, kdf.Threads, kdf.KeyLen)
	return key, kdf, nil
}

func deriveKeyForImport(secret string, kdf exportKDFEnvelope) ([]byte, error) {
	switch kdf.Name {
	case "direct":
		raw, ok := tryDirectAESKey(secret)
		if !ok {
			return nil, fmt.Errorf("DB_EXPORT_KEY is not a valid direct AES key for this export")
		}
		return raw, nil

	case "argon2id":
		salt, err := base64.StdEncoding.DecodeString(kdf.Salt)
		if err != nil {
			return nil, fmt.Errorf("decode kdf salt: %w", err)
		}
		if kdf.Time == 0 || kdf.Memory == 0 || kdf.Threads == 0 || kdf.KeyLen == 0 {
			return nil, fmt.Errorf("invalid argon2id parameters in export")
		}
		return argon2.IDKey([]byte(secret), salt, kdf.Time, kdf.Memory, kdf.Threads, kdf.KeyLen), nil

	default:
		return nil, fmt.Errorf("unsupported kdf: %s", kdf.Name)
	}
}

func cipherLabelForKey(key []byte) string {
	switch len(key) {
	case 16:
		return "AES-128-GCM"
	case 24:
		return "AES-192-GCM"
	case 32:
		return "AES-256-GCM"
	default:
		return "AES-GCM"
	}
}

func encryptAESGCM(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func decryptAESGCM(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size")
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Export writes an encrypted logical JSON export to w.
func Export(src *gorm.DB, w io.Writer, log *slog.Logger) error {
	secret, err := getExportSecretFromEnv()
	if err != nil {
		return err
	}

	key, kdf, err := deriveKeyForExport(secret)
	if err != nil {
		return fmt.Errorf("derive export key: %w", err)
	}

	payload := exportPayload{
		Version:      exportFormatVersion,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		SourceDriver: src.Name(),
		Tables:       make([]exportTable, 0, len(ManagedModelsInDependencyOrder())),
	}

	for _, model := range ManagedModelsInDependencyOrder() {
		sch, err := parseModelSchema(src, model)
		if err != nil {
			return fmt.Errorf("parse schema for export: %w", err)
		}

		rows, err := exportTableRows(src, sch, log)
		if err != nil {
			return fmt.Errorf("export table %s: %w", sch.Table, err)
		}

		payload.Tables = append(payload.Tables, exportTable{
			Name: sch.Table,
			Rows: rows,
		})
	}

	plain, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal export payload: %w", err)
	}

	nonce, ciphertext, err := encryptAESGCM(key, plain)
	if err != nil {
		return fmt.Errorf("encrypt export payload: %w", err)
	}

	envelope := exportEnvelope{
		Format:  exportFormatName,
		Version: exportFormatVersion,
		Cipher:  cipherLabelForKey(key),
		KDF:     kdf,
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Payload: base64.StdEncoding.EncodeToString(ciphertext),
	}

	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal export envelope: %w", err)
	}

	if _, err := w.Write(encoded); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

// Import reads an encrypted logical JSON export from r and restores it into an empty DB.
func Import(db *gorm.DB, r io.Reader, log *slog.Logger) error {
	// Limit import to 512 MiB to prevent OOM from malicious input.
	raw, err := io.ReadAll(io.LimitReader(r, 512*1024*1024))
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return fmt.Errorf("empty import input")
	}

	var envelope exportEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("decode import envelope: %w", err)
	}

	if envelope.Format != exportFormatName {
		return fmt.Errorf("unexpected import format: %q", envelope.Format)
	}
	if envelope.Version != exportFormatVersion {
		return fmt.Errorf("unsupported import format version: %d", envelope.Version)
	}
	if envelope.Nonce == "" {
		return fmt.Errorf("missing nonce")
	}
	if envelope.Payload == "" {
		return fmt.Errorf("missing encrypted payload")
	}

	secret, err := getExportSecretFromEnv()
	if err != nil {
		return err
	}

	key, err := deriveKeyForImport(secret, envelope.KDF)
	if err != nil {
		return fmt.Errorf("derive import key: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return fmt.Errorf("decode nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	plain, err := decryptAESGCM(key, nonce, ciphertext)
	if err != nil {
		return fmt.Errorf("decrypt payload: %w", err)
	}

	var payload exportPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return fmt.Errorf("decode payload json: %w", err)
	}
	if payload.Version != exportFormatVersion {
		return fmt.Errorf("unsupported payload version: %d", payload.Version)
	}

	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback()
			panic(r)
		}
	}()

	if err := ensureImportTargetsAreEmpty(tx); err != nil {
		_ = tx.Rollback()
		return err
	}

	schemaByTable := make(map[string]*schema.Schema, len(ManagedModelsInDependencyOrder()))
	for _, model := range ManagedModelsInDependencyOrder() {
		sch, err := parseModelSchema(tx, model)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("parse schema for import: %w", err)
		}
		schemaByTable[sch.Table] = sch
	}

	for _, tableDump := range payload.Tables {
		sch, ok := schemaByTable[tableDump.Name]
		if !ok {
			_ = tx.Rollback()
			return fmt.Errorf("table %s is not importable by this version", tableDump.Name)
		}

		if log != nil {
			log.Info("db_import",
				slog.String("event", "db_import"),
				slog.String("table", sch.Table),
				slog.Int("rows", len(tableDump.Rows)),
			)
		}

		for _, row := range tableDump.Rows {
			insertRow := make(map[string]any, len(row))

			for col, cell := range row {
				field := sch.FieldsByDBName[col]
				value, err := decodeCell(field, cell)
				if err != nil {
					_ = tx.Rollback()
					return fmt.Errorf("decode %s.%s: %w", sch.Table, col, err)
				}
				insertRow[col] = value
			}

			if err := tx.Table(sch.Table).Create(insertRow).Error; err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("insert into %s: %w", sch.Table, err)
			}
		}
	}

	if tx.Name() == "postgres" {
		if err := resetPostgresSequences(tx); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("reset postgres sequences: %w", err)
		}
	}

	return tx.Commit().Error
}

func parseModelSchema(db *gorm.DB, model any) (*schema.Schema, error) {
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(model); err != nil {
		return nil, err
	}
	return stmt.Schema, nil
}

func ensureImportTargetsAreEmpty(db *gorm.DB) error {
	for _, model := range ManagedModelsInDependencyOrder() {
		var count int64
		if err := db.Unscoped().Model(model).Count(&count).Error; err != nil {
			return fmt.Errorf("count existing rows for import: %w", err)
		}
		if count > 0 {
			sch, err := parseModelSchema(db, model)
			if err != nil {
				return fmt.Errorf("parse schema while checking emptiness: %w", err)
			}
			return fmt.Errorf("import requires an empty target database; table %s already contains %d row(s)", sch.Table, count)
		}
	}
	return nil
}

func exportTableRows(db *gorm.DB, sch *schema.Schema, log *slog.Logger) ([]map[string]encodedCell, error) {
	if log != nil {
		log.Info("db_export",
			slog.String("event", "db_export"),
			slog.String("table", sch.Table),
		)
	}

	query := db.Unscoped().Table(sch.Table)
	for _, pk := range sch.PrimaryFields {
		query = query.Order(pk.DBName)
	}

	rows, err := query.Rows()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	out := make([]map[string]encodedCell, 0)
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}

		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}

		rowObj := make(map[string]encodedCell, len(cols))
		for i, col := range cols {
			field := sch.FieldsByDBName[col]
			cell, err := encodeCell(field, values[i])
			if err != nil {
				return nil, fmt.Errorf("encode %s.%s: %w", sch.Table, col, err)
			}
			rowObj[col] = cell
		}

		out = append(out, rowObj)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func encodeCell(field *schema.Field, value any) (encodedCell, error) {
	if value == nil {
		return encodedCell{Type: "null"}, nil
	}

	targetType := reflect.Type(nil)
	if field != nil {
		targetType = indirectType(field.FieldType)
	}

	if targetType != nil {
		switch {
		case targetType == uuidType:
			s, err := asUUIDString(value)
			if err != nil {
				return encodedCell{}, err
			}
			return encodedCell{Type: "uuid", Value: s}, nil

		case targetType == timeType || targetType == deletedAtType:
			t, err := asTime(value)
			if err != nil {
				return encodedCell{}, err
			}
			return encodedCell{Type: "time", Value: t.UTC().Format(time.RFC3339Nano)}, nil

		case targetType.Kind() == reflect.String:
			return encodedCell{Type: "string", Value: asString(value)}, nil

		case targetType.Kind() == reflect.Bool:
			b, err := asBool(value)
			if err != nil {
				return encodedCell{}, err
			}
			return encodedCell{Type: "bool", Value: b}, nil

		case isSignedIntKind(targetType.Kind()):
			i, err := asInt64(value)
			if err != nil {
				return encodedCell{}, err
			}
			return encodedCell{Type: "int", Value: strconv.FormatInt(i, 10)}, nil

		case isUnsignedIntKind(targetType.Kind()):
			u, err := asUint64(value)
			if err != nil {
				return encodedCell{}, err
			}
			return encodedCell{Type: "uint", Value: strconv.FormatUint(u, 10)}, nil

		case targetType.Kind() == reflect.Float32 || targetType.Kind() == reflect.Float64:
			f, err := asFloat64(value)
			if err != nil {
				return encodedCell{}, err
			}
			return encodedCell{Type: "float", Value: strconv.FormatFloat(f, 'g', -1, 64)}, nil

		case targetType.Kind() == reflect.Slice && targetType.Elem().Kind() == reflect.Uint8:
			b, err := asBytes(value)
			if err != nil {
				return encodedCell{}, err
			}
			return encodedCell{Type: "bytes", Value: base64.StdEncoding.EncodeToString(b)}, nil
		}
	}

	switch v := value.(type) {
	case time.Time:
		return encodedCell{Type: "time", Value: v.UTC().Format(time.RFC3339Nano)}, nil
	case []byte:
		return encodedCell{Type: "bytes", Value: base64.StdEncoding.EncodeToString(v)}, nil
	case string:
		return encodedCell{Type: "string", Value: v}, nil
	case bool:
		return encodedCell{Type: "bool", Value: v}, nil
	case int:
		return encodedCell{Type: "int", Value: strconv.FormatInt(int64(v), 10)}, nil
	case int8:
		return encodedCell{Type: "int", Value: strconv.FormatInt(int64(v), 10)}, nil
	case int16:
		return encodedCell{Type: "int", Value: strconv.FormatInt(int64(v), 10)}, nil
	case int32:
		return encodedCell{Type: "int", Value: strconv.FormatInt(int64(v), 10)}, nil
	case int64:
		return encodedCell{Type: "int", Value: strconv.FormatInt(v, 10)}, nil
	case uint:
		return encodedCell{Type: "uint", Value: strconv.FormatUint(uint64(v), 10)}, nil
	case uint8:
		return encodedCell{Type: "uint", Value: strconv.FormatUint(uint64(v), 10)}, nil
	case uint16:
		return encodedCell{Type: "uint", Value: strconv.FormatUint(uint64(v), 10)}, nil
	case uint32:
		return encodedCell{Type: "uint", Value: strconv.FormatUint(uint64(v), 10)}, nil
	case uint64:
		return encodedCell{Type: "uint", Value: strconv.FormatUint(v, 10)}, nil
	case float32:
		return encodedCell{Type: "float", Value: strconv.FormatFloat(float64(v), 'g', -1, 64)}, nil
	case float64:
		return encodedCell{Type: "float", Value: strconv.FormatFloat(v, 'g', -1, 64)}, nil
	default:
		return encodedCell{Type: "json", Value: v}, nil
	}
}

func decodeCell(field *schema.Field, cell encodedCell) (any, error) {
	switch cell.Type {
	case "null":
		return nil, nil

	case "string":
		s, ok := cell.Value.(string)
		if !ok {
			return nil, fmt.Errorf("invalid string cell")
		}
		return s, nil

	case "bool":
		b, ok := cell.Value.(bool)
		if !ok {
			return nil, fmt.Errorf("invalid bool cell")
		}
		return b, nil

	case "int":
		s, ok := cell.Value.(string)
		if !ok {
			return nil, fmt.Errorf("invalid int cell")
		}
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, err
		}
		return i, nil

	case "uint":
		s, ok := cell.Value.(string)
		if !ok {
			return nil, fmt.Errorf("invalid uint cell")
		}
		u, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, err
		}
		return u, nil

	case "float":
		s, ok := cell.Value.(string)
		if !ok {
			return nil, fmt.Errorf("invalid float cell")
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil, err
		}
		return f, nil

	case "time":
		s, ok := cell.Value.(string)
		if !ok {
			return nil, fmt.Errorf("invalid time cell")
		}
		t, err := parseFlexibleTime(s)
		if err != nil {
			return nil, err
		}
		return t, nil

	case "uuid":
		s, ok := cell.Value.(string)
		if !ok {
			return nil, fmt.Errorf("invalid uuid cell")
		}
		return s, nil

	case "bytes":
		s, ok := cell.Value.(string)
		if !ok {
			return nil, fmt.Errorf("invalid bytes cell")
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		return b, nil

	case "json":
		return cell.Value, nil

	default:
		if field != nil && indirectType(field.FieldType).Kind() == reflect.String {
			if s, ok := cell.Value.(string); ok {
				return s, nil
			}
		}
		return nil, fmt.Errorf("unsupported cell type: %s", cell.Type)
	}
}

func resetPostgresSequences(db *gorm.DB) error {
	for _, model := range ManagedModelsInDependencyOrder() {
		sch, err := parseModelSchema(db, model)
		if err != nil {
			return err
		}

		if len(sch.PrimaryFields) != 1 {
			continue
		}

		pk := sch.PrimaryFields[0]
		pkType := indirectType(pk.FieldType)
		if pkType == nil {
			continue
		}
		if !isSignedIntKind(pkType.Kind()) && !isUnsignedIntKind(pkType.Kind()) {
			continue
		}

		tableQuoted := quoteIdent(sch.Table, db.Name())
		columnQuoted := quoteIdent(pk.DBName, db.Name())

		query := fmt.Sprintf(`
SELECT setval(
	pg_get_serial_sequence('%s', '%s'),
	COALESCE(MAX(%s), 1),
	MAX(%s) IS NOT NULL
)
FROM %s
`, sch.Table, pk.DBName, columnQuoted, columnQuoted, tableQuoted)

		if err := db.Exec(query).Error; err != nil {
			return fmt.Errorf("reset sequence for %s.%s: %w", sch.Table, pk.DBName, err)
		}
	}

	return nil
}

func indirectType(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t
}

func isSignedIntKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	default:
		return false
	}
}

func isUnsignedIntKind(k reflect.Kind) bool {
	switch k {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return fmt.Sprint(x)
	}
}

func asBytes(v any) ([]byte, error) {
	switch x := v.(type) {
	case []byte:
		return x, nil
	case string:
		return []byte(x), nil
	default:
		return nil, fmt.Errorf("cannot convert %T to []byte", v)
	}
}

func asBool(v any) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case int:
		return x != 0, nil
	case int64:
		return x != 0, nil
	case []byte:
		switch strings.ToLower(strings.TrimSpace(string(x))) {
		case "1", "t", "true":
			return true, nil
		case "0", "f", "false":
			return false, nil
		}
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "1", "t", "true":
			return true, nil
		case "0", "f", "false":
			return false, nil
		}
	}
	return false, fmt.Errorf("cannot convert %T to bool", v)
}

func asInt64(v any) (int64, error) {
	switch x := v.(type) {
	case int:
		return int64(x), nil
	case int8:
		return int64(x), nil
	case int16:
		return int64(x), nil
	case int32:
		return int64(x), nil
	case int64:
		return x, nil
	case uint:
		if uint64(x) > math.MaxInt64 {
			return 0, fmt.Errorf("uint overflows int64")
		}
		return int64(x), nil
	case uint8:
		return int64(x), nil
	case uint16:
		return int64(x), nil
	case uint32:
		return int64(x), nil
	case uint64:
		if x > math.MaxInt64 {
			return 0, fmt.Errorf("uint64 overflows int64")
		}
		return int64(x), nil
	case []byte:
		return strconv.ParseInt(strings.TrimSpace(string(x)), 10, 64)
	case string:
		return strconv.ParseInt(strings.TrimSpace(x), 10, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to int64", v)
	}
}

func asUint64(v any) (uint64, error) {
	switch x := v.(type) {
	case uint:
		return uint64(x), nil
	case uint8:
		return uint64(x), nil
	case uint16:
		return uint64(x), nil
	case uint32:
		return uint64(x), nil
	case uint64:
		return x, nil
	case int:
		if x < 0 {
			return 0, fmt.Errorf("negative int cannot convert to uint64")
		}
		return uint64(x), nil
	case int8:
		if x < 0 {
			return 0, fmt.Errorf("negative int8 cannot convert to uint64")
		}
		return uint64(x), nil
	case int16:
		if x < 0 {
			return 0, fmt.Errorf("negative int16 cannot convert to uint64")
		}
		return uint64(x), nil
	case int32:
		if x < 0 {
			return 0, fmt.Errorf("negative int32 cannot convert to uint64")
		}
		return uint64(x), nil
	case int64:
		if x < 0 {
			return 0, fmt.Errorf("negative int64 cannot convert to uint64")
		}
		return uint64(x), nil
	case []byte:
		return strconv.ParseUint(strings.TrimSpace(string(x)), 10, 64)
	case string:
		return strconv.ParseUint(strings.TrimSpace(x), 10, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to uint64", v)
	}
}

func asFloat64(v any) (float64, error) {
	switch x := v.(type) {
	case float32:
		return float64(x), nil
	case float64:
		return x, nil
	case int:
		return float64(x), nil
	case int8:
		return float64(x), nil
	case int16:
		return float64(x), nil
	case int32:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case uint:
		return float64(x), nil
	case uint8:
		return float64(x), nil
	case uint16:
		return float64(x), nil
	case uint32:
		return float64(x), nil
	case uint64:
		return float64(x), nil
	case []byte:
		return strconv.ParseFloat(strings.TrimSpace(string(x)), 64)
	case string:
		return strconv.ParseFloat(strings.TrimSpace(x), 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}

func asUUIDString(v any) (string, error) {
	switch x := v.(type) {
	case uuid.UUID:
		return x.String(), nil
	case [16]byte:
		u, err := uuid.FromBytes(x[:])
		if err != nil {
			return "", err
		}
		return u.String(), nil
	case []byte:
		if len(x) == 16 {
			u, err := uuid.FromBytes(x)
			if err != nil {
				return "", err
			}
			return u.String(), nil
		}
		s := strings.TrimSpace(string(x))
		if _, err := uuid.Parse(s); err != nil {
			return "", err
		}
		return s, nil
	case string:
		s := strings.TrimSpace(x)
		if _, err := uuid.Parse(s); err != nil {
			return "", err
		}
		return s, nil
	default:
		return "", fmt.Errorf("cannot convert %T to uuid", v)
	}
}

func asTime(v any) (time.Time, error) {
	switch x := v.(type) {
	case time.Time:
		return x, nil
	case []byte:
		return parseFlexibleTime(strings.TrimSpace(string(x)))
	case string:
		return parseFlexibleTime(strings.TrimSpace(x))
	default:
		return time.Time{}, fmt.Errorf("cannot convert %T to time.Time", v)
	}
}

func parseFlexibleTime(s string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		time.DateTime,
		time.DateOnly,
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported time format: %q", s)
}

func quoteIdent(name, dialect string) string {
	switch dialect {
	case "mysql":
		return "`" + strings.ReplaceAll(name, "`", "``") + "`"
	case "postgres", "sqlite":
		fallthrough
	default:
		return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
	}
}

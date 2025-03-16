package main

import (
	"crypto/tls"
	"database/sql"
	"strings"

	"time"

	"embed"
	"encoding/json"
	"fmt"

	"os"
	"strconv"

	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/redis/go-redis/v9"
)

// NOTE: pesan-web - APPLICATION
// *this is for an nvim easy jump; consider it as table of contents

//go:embed .well-known
var wellKnownFS embed.FS

var (
	db         *sql.DB
	statements map[StatementKey]*sql.Stmt
	cache      *redis.Client
	wbAuthn    *webauthn.WebAuthn
)

func main() {
	var certPem []byte
	keyPem, err := os.ReadFile(os.Getenv("WEB_PRIVATE_KEY_PATH"))
	if err != nil {
		fmt.Printf("[FATAL] invalid private key: %v\n", err)
	}
	certPem, err = os.ReadFile(os.Getenv("WEB_CERT_PATH"))
	if err != nil {
		fmt.Printf("[FATAL] invalid cert: %v\n", err)
	}
	var certTls tls.Certificate
	certTls, err = tls.X509KeyPair(certPem, keyPem)
	cfg := &tls.Config{Certificates: []tls.Certificate{certTls}}
	var port int64
	port, err = strconv.ParseInt(os.Getenv("PORT"), 10, 32)
	if err != nil {
		fmt.Printf("[WARN] %v\n", err)
		port = 3000
	}

	establishDb()
	prepareStatements()
	establishCache()
	configureWebAuthn()

	router := http.NewServeMux()
	// NOTE: serve .well-known file
	router.Handle("/", http.FileServerFS(wellKnownFS))

	// NOTE: endpoints
	router.HandleFunc("POST /public-key/assert/{challenge}", verifyAssertation)
	router.HandleFunc("POST /public-key/attest/discoverable/{challenge}", verifyDiscoverableAttestation)

	srv := http.Server{
		Addr:      fmt.Sprintf("%s:%d", os.Getenv("HOST"), port),
		Handler:   logger(router),
		TLSConfig: cfg,
	}
	fmt.Printf("[INFO] listening to port %s..\n", srv.Addr)

	//err = srv.ListenAndServeTLS("", "")
	err = srv.ListenAndServe()
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}

// NOTE: pesan-web - MIDDLEWARES
// NOTE: pesan-web/middlewares/logger
type wrappedWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *wrappedWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
	w.statusCode = statusCode
}

func logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &wrappedWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}
		next.ServeHTTP(wrapped, r)
		log.Printf("[INFO]\t%d\t%s\t%s\t%s", wrapped.statusCode, r.Method, r.RequestURI, time.Since(start))
	})
}

// NOTE: pesan-web - WEBAUTHN
func configureWebAuthn() {
	host, androidOrigin := os.Getenv("WBAUTHN_RP_ID"), fmt.Sprintf("android:apk-key-hash:%s", os.Getenv("ANDROID_KEY_HASH"))
	origin := fmt.Sprintf("%s://%s", os.Getenv("WEB_SCHEME"), host)

	config := &webauthn.Config{
		RPDisplayName: "Pesan authentication",
		RPID:          host,
		RPOrigins:     []string{origin, androidOrigin},
	}

	var err error
	wbAuthn, err = webauthn.New(config)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
		return
	}

	fmt.Println("[INFO] webauthn configured!")
}

// NOTE: pesan-web - DATABASE
type StatementKey int

const (
	ReadUserWithPasskeys StatementKey = iota
	CreateAnUser
	CreateAPasskey
	UpdateAPasskey
)

func establishDb() {
	var pgPort int64
	var pwd []byte
	pgPort, err := strconv.ParseInt(os.Getenv("POSTGRES_PORT"), 10, 32)

	if err != nil {
		fmt.Printf("[WARN] %v\n", err)
		pgPort = 5432
	}
	pwd, err = os.ReadFile(os.Getenv("POSTGRES_PASSWORD_FILE"))
	if err != nil {
		log.Fatalf("[FATAL] %v\n", err)
		return
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		os.Getenv("POSTGRES_USER"),
		pwd,
		os.Getenv("POSTGRES_HOST"),
		pgPort,
		os.Getenv("POSTGRES_DB"))

	db, err = sql.Open("pgx", dsn)
	if err != nil {
		log.Fatalf("[FATAL] unable to use data source name -\n%v\n", err)
		return
	}

	fmt.Println("[INFO] db connected!")
}

func prepareStatements() {
	temp := make(map[StatementKey]*sql.Stmt)

	queries := map[StatementKey]string{
		ReadUserWithPasskeys: `	
			SELECT  
				user_handle,	
				display_name,
				passkey_id,
				public_key,
				attestation_type,
				transport,
				flags,
				authenticator_aaguid,
				sign_count
			FROM 
				user_passkeys
			WHERE 
				user_id = $1
		`,
		CreateAnUser: `INSERT INTO
				users(user_id, user_handle, display_name)
			VALUES( $1, $2, $3)`,
		CreateAPasskey: `
			INSERT INTO
				passkeys(passkey_id, public_key, attestation_type, transport, flags, authenticator_aaguid, user_id)
			VALUES( $1, $2, $3, $4, $5, $6, $7)
		`,
		UpdateAPasskey: `
			UPDATE
				passkeys
			SET
				(public_key, attestation_type, transport, flags, authenticator_aaguid, sign_count) = ($1, $2, $3, $4, $5, $6)
			WHERE
				passkey_id = $7
		`,
	}

	for key, query := range queries {
		stmt, err := db.Prepare(query)
		if err != nil {
			log.Fatalf("[ERROR] error preparing statement for %v: %v", key, err)
			defer db.Close()
			return
		}
		temp[key] = stmt
	}

	fmt.Println("[INFO] sql statements prepared!")
	statements = temp
}

// NOTE: pesan-web - CACHE
func establishCache() {
	rdHost, rdPort := os.Getenv("RDS_HOST"), os.Getenv("RDS_PORT")
	if len(rdHost) == 0 {
		fmt.Println("[WARN] redis host isn't specified!")
		rdHost = "cache"
	}
	port, err := strconv.ParseInt(rdPort, 10, 32)
	if err != nil {
		fmt.Println("[WARN] redis port isn't specified!")
		port = 6379
	}
	cache = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", rdHost, port),
		Password: "",
		DB:       0,
		Protocol: 2,
	})

	fmt.Println("[INFO] cache established!")
}

// NOTE: pesan-web - SESSIONS
type User struct {
	Id          uuid.UUID             `json:"id"`
	UserHandle  string                `json:"user_handle"`
	DisplayName string                `json:"display_name"`
	Credentials []webauthn.Credential `json:"credentials"`
}

func (u *User) WebAuthnID() []byte {
	return []byte(u.Id.String())
}

func (u *User) WebAuthnName() string {
	return u.UserHandle
}

func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// NOTE: pesan-web - ASSERT
func verifyAssertation(w http.ResponseWriter, r *http.Request) {

	challengeId := r.PathValue("challenge")
	cacheKey := fmt.Sprintf("asserts:%s", challengeId)

	ctx := r.Context()

	cachedUser, err := cache.JSONGet(ctx, cacheKey, ".user").Result()
	if err != nil {
		http.Error(w, "[ERROR] WEB - session timeout", http.StatusRequestTimeout)
		return
	}

	var cacheSession string
	cacheSession, err = cache.JSONGet(ctx, cacheKey, ".session").Result()
	if err != nil {
		http.Error(w, "[ERROR] WEB - session timeout", http.StatusRequestTimeout)
		return
	}

	var user User
	err = json.Unmarshal([]byte(cachedUser), &user)
	if err != nil {
		cache.JSONClear(ctx, cacheKey, "$")
		http.Error(w, fmt.Sprintf("[ERROR] WEB - %v", err), http.StatusFailedDependency)
		return
	}

	var session webauthn.SessionData
	err = json.Unmarshal([]byte(cacheSession), &session)
	if err != nil {
		cache.JSONClear(ctx, cacheKey, "$")
		http.Error(w, fmt.Sprintf("[ERROR] WEB - %v", err), http.StatusFailedDependency)
		return
	}

	var cred *webauthn.Credential
	cred, err = wbAuthn.FinishRegistration(&user, session, r)
	if err != nil {
		cache.JSONClear(ctx, cacheKey, "$")
		http.Error(w, fmt.Sprintf("[ERROR] WEB - %v", err), http.StatusInternalServerError)
		return
	}

	_, err = statements[CreateAnUser].Exec(user.Id, user.UserHandle, user.DisplayName)
	if err != nil {
		http.Error(w, fmt.Sprintf("[ERROR] WEB - %v", err), http.StatusInternalServerError)
		return
	}

	_, err = statements[CreateAPasskey].Exec(
		cred.ID,
		cred.PublicKey,
		cred.AttestationType,
		cred.Transport,
		cred.Flags,
		cred.Authenticator.AAGUID,
		user.Id,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("[ERROR] WEB - %v", err), http.StatusInternalServerError)
		return
	}

	// NOTE: slightly extend for the case of legit verification but at the verge of session ending
	cache.ExpireAt(ctx, cacheKey, time.Now().Add(30*time.Second)).Result()

	w.WriteHeader(http.StatusAccepted)
}

// NOTE: pesan-web - ATTEST
func verifyDiscoverableAttestation(w http.ResponseWriter, r *http.Request) {
	challengeId := r.PathValue("challenge")
	cacheKey := fmt.Sprintf("attests:%s", challengeId)

	ctx := r.Context()

	cachedSession, err := cache.JSONGet(ctx, cacheKey, "$").Result()
	if err != nil || len(cachedSession) == 0 {
		http.Error(w, "[ERROR] WEB - session timeout", http.StatusRequestTimeout)
		return
	}

	// NOTE: remove [] to unmarshal to json
	cachedSession = strings.TrimPrefix(cachedSession, "[")
	cachedSession = strings.TrimSuffix(cachedSession, "]")

	var session webauthn.SessionData
	err = json.Unmarshal([]byte(cachedSession), &session)
	if err != nil {
		cache.JSONClear(ctx, cacheKey, "$")
		http.Error(w, "[ERROR] WEB - session corrupted", http.StatusFailedDependency)
		return
	}

	var cred *webauthn.Credential
	cred, err = wbAuthn.FinishDiscoverableLogin(readUser, session, r)
	if err != nil {
		cache.JSONClear(ctx, cacheKey, "$")
		http.Error(w, fmt.Sprintf("[ERROR] WEB - %v", err), http.StatusFailedDependency)
		return
	}

	_, err = statements[UpdateAPasskey].Exec(cred.PublicKey, cred.AttestationType, cred.Transport, cred.Flags, cred.Authenticator.AAGUID, cred.Authenticator.SignCount)
	// NOTE: ignore err

	w.WriteHeader(http.StatusAccepted)
	var result int
	result, err = w.Write(cred.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("[ERROR] WEB - %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("[INFO] /attest/discoverable result: %d", result)
}

func readUser(rawID, userHandle []byte) (webauthn.User, error) {
	userId, err := uuid.Parse(string(userHandle))
	if err != nil {
		return nil, err
	}
	rows, err := statements[ReadUserWithPasskeys].Query(userId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var username, displayName string
	creds := []webauthn.Credential{}
	for rows.Next() {
		var cred webauthn.Credential
		var transport string
		var flags []byte
		if err = rows.Scan(&username, &displayName, &cred.ID, &cred.PublicKey, &cred.AttestationType, &transport, &flags, &cred.Authenticator.AAGUID, &cred.Authenticator.SignCount); err != nil {
			// TODO: log error
			continue
		}

		cred.Transport = append(cred.Transport, protocol.AuthenticatorTransport(transport))
		err = json.Unmarshal(flags, &cred.Flags)

		creds = append(creds, cred)
	}

	return &User{
		Id:          userId,
		UserHandle:  username,
		DisplayName: displayName,
		Credentials: creds,
	}, nil
}

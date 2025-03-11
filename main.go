package main

import (
	"crypto/tls"
	"time"

	"embed"
	"encoding/json"
	"fmt"

	"os"
	"strconv"

	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/redis/go-redis/v9"
)

// NOTE: web - APPLICATION
// *this is for an nvim easy jump; consider it as table of contents

//go:embed .well-known
var wellKnownFS embed.FS

var (
	cache   *redis.Client
	wbAuthn *webauthn.WebAuthn
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

	establishCache()
	configureWebAuthn()

	router := http.NewServeMux()
	// NOTE: serve .well-known file
	router.Handle("/", http.FileServerFS(wellKnownFS))

	// NOTE: endpoints
	router.HandleFunc("POST /public-key/assert/{challenge}", verifyAssertation)

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

// NOTE: web - MIDDLEWARES
// NOTE: web/middlewares/logger
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

// NOTE: web - WEBAUTHN
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

// NOTE: web - CACHE
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

// NOTE: web - SESSIONS
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

// NOTE: web - ASSERT
func verifyAssertation(w http.ResponseWriter, r *http.Request) {

	challengeId := r.PathValue("challenge")
	cacheKey := fmt.Sprintf("asserts:%s", challengeId)

	ctx := r.Context()

	cachedUser, err := cache.JSONGet(ctx, cacheKey, ".user").Result()

	var cacheSession string
	cacheSession, err = cache.JSONGet(ctx, cacheKey, ".session").Result()
	if err != nil {
		http.Error(w, "[ERROR] WEB - session timeout", http.StatusRequestTimeout)
		return
	}

	var user User
	err = json.Unmarshal([]byte(cachedUser), &user)
	if err != nil {
		http.Error(w, fmt.Sprintf("[ERROR] WEB - %v", err), http.StatusFailedDependency)
		cache.JSONClear(ctx, cacheKey, "$")
		return
	}

	var session webauthn.SessionData
	err = json.Unmarshal([]byte(cacheSession), &session)
	if err != nil {
		http.Error(w, fmt.Sprintf("[ERROR] WEB - %v", err), http.StatusFailedDependency)
		cache.JSONClear(ctx, cacheKey, "$")
		return
	}

	_, err = wbAuthn.FinishRegistration(&user, session, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("[ERROR] WEB - %v", err), http.StatusInternalServerError)
		cache.JSONClear(ctx, cacheKey, "$")
		return
	}

	// NOTE: slightly extend for the case of legit verification but at the verge of session ending
	cache.ExpireAt(ctx, cacheKey, time.Now().Add(30*time.Second)).Result()

	w.WriteHeader(http.StatusAccepted)
}

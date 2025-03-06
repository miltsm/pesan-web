package session

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type Session interface {
	PostRequestAssertation(w http.ResponseWriter, r *http.Request)
	PostAssertPublicKey(w http.ResponseWriter, r *http.Request)
}

type session struct {
	db    *sql.DB
	cache *redis.Client

	readUserHandleStmt, createUserStmt, createPublicKeyStmt *sql.Stmt

	wbAuthn webauthn.WebAuthn

	secretKey string
}

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

type WebAuthnCacheData struct {
	User    User                 `json:"user"`
	Session webauthn.SessionData `json:"session"`
	// NOTE: this is prevent spam call from the same user
	// TODO: rate limit
	CredentialCreation protocol.CredentialCreation `json:"credential_creation"`
}

type AttestChallengeResponse struct {
	Challenge []byte `json:"challenge"`
}

type OnboardResponse struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken *string `json:"refresh_token,omitempty"`
}

func New(db *sql.DB, cache redis.Client) Session {
	// NOTE: prepare sql: read user by user handle
	readUserByHandleStmt, err := db.Prepare(`
		SELECT
			user_id, user_handle, display_name
		FROM
			users
		WHERE
			user_handle = $1
		`)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	var createUserStmt, createPublicKeyStmt *sql.Stmt

	// NOTE: prepare sql: create new user
	createUserStmt, err = db.Prepare(`
		INSERT INTO
			users(user_handle, display_name)
		VALUES( $1, $2)
		`)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	// NOTE: prepare sql: create new passkey
	createPublicKeyStmt, err = db.Prepare(`
		INSERT INTO
			passkeys(passkey_id, public_key, attestation_type, transport, flags, authenticator_aaguid, sign_count, user_id)
		VALUES( $1, $2, $3, $4, $5, $6, $7, $8)
		`)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	// NOTE: webauthn
	rpId := os.Getenv("WBAUTHN_RP_ID")
	androidOrigin := fmt.Sprintf("android:apk-key-hash:%s", os.Getenv("ANDROID_KEY_HASH"))
	config := &webauthn.Config{
		RPDisplayName: "Pesan authentication",
		RPID:          rpId,
		RPOrigins:     []string{androidOrigin, fmt.Sprintf("%s://%s", os.Getenv("WEB_SCHEME"), rpId)},
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Second * 60,
				TimeoutUVD: time.Second * 60,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Second * 60,
				TimeoutUVD: time.Second * 60,
			},
		},
	}

	var wba *webauthn.WebAuthn
	wba, err = webauthn.New(config)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	// NOTE: get jwt secret
	var apiSecret []byte
	apiSecret, err = os.ReadFile(os.Getenv("JWT_SECRET_PATH"))
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	return &session{
		db:                  db,
		cache:               &cache,
		readUserHandleStmt:  readUserByHandleStmt,
		createUserStmt:      createUserStmt,
		createPublicKeyStmt: createPublicKeyStmt,
		wbAuthn:             *wba,
		secretKey:           string(apiSecret),
	}
}

func (s *session) PostRequestAssertation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userHandle, displayName := r.FormValue("user_handle"), r.FormValue("display_name")
	if len(userHandle) == 0 {
		http.Error(w, "user handle can't be empty", http.StatusBadRequest)
		return
	}

	err := s.readUserHandleStmt.QueryRow(userHandle).Scan()
	if err != nil {
		fmt.Printf("[ERROR] line 167:\n%v\n", err)
		// NOTE: Check if user re-request again
		cacheKey := fmt.Sprintf("onboardings:%s", userHandle)
		//s.cache.JSONGet(ctx, )
		// NOTE: Check if new user
		if errors.Is(err, sql.ErrNoRows) {
			tempUser := &User{
				UserHandle:  userHandle,
				DisplayName: displayName,
			}

			var creation *protocol.CredentialCreation
			var session *webauthn.SessionData
			creation, session, err := s.wbAuthn.BeginMediatedRegistration(tempUser, protocol.MediationOptional)
			if err != nil {
				http.Error(w, fmt.Sprintf("error during registration: %v", err), http.StatusInternalServerError)
				return
			}

			// NOTE: Cache session
			cacheData := &WebAuthnCacheData{
				User:               *tempUser,
				Session:            *session,
				CredentialCreation: *creation,
			}
			jsonCacheData, err := json.Marshal(cacheData)
			if err != nil {
				http.Error(w, fmt.Sprintf("temp user json marshaling failed: %v", err), http.StatusInternalServerError)
				return
			}

			var cacheResult string
			cacheResult, err = s.cache.JSONSet(r.Context(), cacheKey, "$", jsonCacheData).Result()
			if err != nil || strings.Compare(cacheResult, "OK") != 0 {
				http.Error(w, fmt.Sprintf("error setting cache: %v", err), http.StatusInternalServerError)
				return
			}

			// NOTE: set expiry time for this cache
			var expiredAt = session.Expires.Local().Sub(time.Now().Local())
			var expiring bool
			expiring, err = s.cache.Expire(ctx, cacheKey, expiredAt).Result()
			if err != nil || !expiring {
				http.Error(w, "error setting cache expiration", http.StatusInternalServerError)
				return
			}

			// NOTE: marshal and return result
			var options []byte
			options, err = json.Marshal(creation.Response)
			if err != nil {
				http.Error(w, "unexpected error!", http.StatusInternalServerError)
				return
			}
			fmt.Println(string(options))

			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)

			encoder := json.NewEncoder(w)
			err = encoder.Encode(&AttestChallengeResponse{
				Challenge: options,
			})
			if err != nil {
				http.Error(w, "unable encode result (json)", http.StatusInternalServerError)
				return
			}
			return
		} else {
			http.Error(w, "unable to create challenge", http.StatusInternalServerError)
			return
		}
	}

	http.Error(w, "user already exists with the given userhandle", http.StatusConflict)
}

func (s *session) PostAssertPublicKey(w http.ResponseWriter, r *http.Request) {
	userHandle := r.FormValue("user_handle")
	if len(userHandle) == 0 {
		http.Error(w, "user handle can't be empty", http.StatusBadRequest)
		return
	}

	// NOTE: Get cache data to verify the public key provided
	ctx := r.Context()
	cacheKey := fmt.Sprintf("onboardings:%s", userHandle)
	userCache, err := s.cache.JSONGet(ctx, cacheKey, ".user").Result()
	var sessionCache string
	sessionCache, err = s.cache.JSONGet(ctx, cacheKey, ".session").Result()
	if err != nil {
		http.Error(w, "session ended!", http.StatusRequestTimeout)
		return
	}

	var marshalUser User
	userId := uuid.New()
	marshalUser.Id = userId
	err = json.Unmarshal([]byte(userCache), &marshalUser)
	if err != nil {
		http.Error(w, "session corrupted: please try again", http.StatusFailedDependency)
		return
	}

	var marshalSession webauthn.SessionData
	err = json.Unmarshal([]byte(sessionCache), &marshalSession)
	if err != nil {
		http.Error(w, "session corrupted: please try again", http.StatusFailedDependency)
		return
	}

	var credential *webauthn.Credential
	credential, err = s.wbAuthn.FinishRegistration(&marshalUser, marshalSession, r)
	if err != nil {
		http.Error(w, "error verifying public key", http.StatusBadRequest)
		return
	}

	// NOTE: create user; if new
	err = s.readUserHandleStmt.QueryRow(userHandle).Err()
	if errors.Is(err, sql.ErrNoRows) {
		_, err = s.createUserStmt.Exec(marshalUser.UserHandle, marshalUser.DisplayName)
		if err != nil {
			http.Error(w, "unable to create user", http.StatusInternalServerError)
			return
		}
	}

	// NOTE: create passkey
	_, err = s.createPublicKeyStmt.Exec(credential.ID, credential.PublicKey, credential.AttestationType, credential.Transport, credential.Flags, credential.Authenticator.AAGUID, credential.Authenticator.SignCount, userId)
	if err != nil {
		http.Error(w, "unable to create passkey", http.StatusInternalServerError)
		return
	}

	// NOTE: generate jwt token
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "pesan-web",
		Subject:   userHandle,
		ID:        uuid.New().String(),
		Audience:  []string{"seller"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	var accessToken string
	accessToken, err = token.SignedString(s.secretKey)
	if err != nil {
		http.Error(w, "unable to generate user access token", http.StatusInternalServerError)
		return
	}

	// NOTE: refresh_tokens are meant for user that login/sign up via password
	encoder := json.NewEncoder(w)
	err = encoder.Encode(&OnboardResponse{
		AccessToken: accessToken,
	})
	if err != nil {
		http.Error(w, "unable to return data", http.StatusInternalServerError)
	}
}

package session

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

type DiscoverAssertionReply struct {
	Challenge  []byte    `json:"challenge"`
	ValidUntil time.Time `json:"valid_util"`
	VerifyLink string    `json:"verify_link"`
}

func (s *session) PostPublicKeyAssertDiscover(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	assertation, session, err := s.wbAuthn.BeginDiscoverableMediatedLogin(protocol.MediationConditional)
	if err != nil {
		http.Error(w, "unable to generate assertation(discover)", http.StatusInternalServerError)
		return
	}

	// NOTE: cache session
	cacheKey := fmt.Sprintf("asserts:%s", session.Challenge)
	marshaledSession, err := json.Marshal(session)
	if err != nil {
		http.Error(w, "unable to marshal session data", http.StatusInternalServerError)
		return
	}
	var cacheRes string
	cacheRes, err = s.cache.JSONSet(r.Context(), cacheKey, "$", marshaledSession).Result()
	if err != nil || strings.Compare(cacheRes, "OK") != 0 {
		http.Error(w, "unable to cache session for verification", http.StatusInternalServerError)
		return
	}
	var isExpiring bool
	isExpiring, err = s.cache.ExpireAt(ctx, cacheKey, session.Expires).Result()
	if !isExpiring || err != nil {
		http.Error(w, "unable to expire session; aborted", http.StatusInternalServerError)
		return
	}

	var marshaledChallenge []byte
	marshaledChallenge, err = json.Marshal(assertation.Response)
	if err != nil {
		http.Error(w, "unable to marshal result", http.StatusInternalServerError)
		return
	}

	// NOTE: set headers
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	encoder := json.NewEncoder(w)
	err = encoder.Encode(&DiscoverAssertionReply{
		Challenge:  marshaledChallenge,
		ValidUntil: session.Expires,
		VerifyLink: fmt.Sprintf("/public-key/attest/%v/verify", session.Challenge),
	})
	if err != nil {
		http.Error(w, "unable to encode result", http.StatusInternalServerError)
		return
	}
}

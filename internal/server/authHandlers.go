package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/dnflash/demo-p1-go-auth-service/internal/database"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

func (s Server) loginHandler() http.HandlerFunc {
	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	type response struct {
		AccessToken    string `json:"accessToken"`
		RefreshToken   string `json:"refreshToken"`
		RefreshTokenID string `json:"refreshTokenId"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := request{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("loginHandler: Error decoding JSON, err: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		u, err := s.UserDB.FindUserByUsername(r.Context(), req.Username)
		if err != nil {
			log.Printf("loginHandler: Error finding User, err: %v", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		err = bcrypt.CompareHashAndPassword(u.Password, []byte(req.Password))
		if err != nil {
			log.Printf("loginHandler: Error comparing hash and password for username: %s, err: %v", u.Username, err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		at, rt, rtID, err := s.issueNewAccessAndRefreshToken(r.Context(), u)
		if err != nil {
			log.Printf("loginHandler: Error issuing new access and refresh token for username: %s, err: %v", u.Username, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		s.writeJsonResponse(w, response{AccessToken: at, RefreshToken: rt, RefreshTokenID: rtID}, http.StatusOK)
	}
}

func (s Server) refreshHandler() http.HandlerFunc {
	type request struct {
		RefreshToken   string `json:"refreshToken"`
		RefreshTokenID string `json:"refreshTokenId"`
	}
	type response struct {
		AccessToken    string `json:"accessToken"`
		RefreshToken   string `json:"refreshToken"`
		RefreshTokenID string `json:"refreshTokenId"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := request{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("refreshHandler: Error decoding JSON, err: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		token, err := jwt.Parse([]byte(req.RefreshToken), jwt.WithKey(jwa.HS256, s.RefreshTokenSecret), jwt.WithValidate(true))
		if err != nil {
			log.Printf("refreshHandler: Failed to validate refresh token, err: %v", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		typeClaim, ok := token.Get("type")
		if !ok {
			log.Printf("refreshHandler: Invalid refresh token, missing type")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		tokenType, ok := typeClaim.(string)
		if !ok || tokenType != "refresh-token" {
			log.Printf("refreshHandler: Invalid token type")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		rt, err := s.AuthDB.FindRefreshTokenByID(r.Context(), req.RefreshTokenID)
		if err != nil {
			log.Printf("refreshHandler: Error finding RefreshToken, err: %v", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		refreshTokenHash := sha256.New()
		refreshTokenHash.Write([]byte(req.RefreshToken))
		err = bcrypt.CompareHashAndPassword(rt.Token, refreshTokenHash.Sum(nil))
		if err != nil {
			log.Printf("refreshHandler: Error comparing hash and refresh token, err: %v", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		u, err := s.UserDB.FindUserByID(r.Context(), rt.UserID.Hex())
		if err != nil {
			log.Printf("refreshHandler: Error finding User, err: %v", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		at, newRT, newRTID, err := s.issueNewAccessAndRefreshToken(r.Context(), u)
		if err != nil {
			log.Printf("refreshHandler: Error issuing new access and refresh token for username: %s, err: %v", u.Username, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// Delete old refresh token
		err = s.AuthDB.DeleteRefreshTokenByID(r.Context(), req.RefreshTokenID)
		if err != nil {
			log.Printf("refreshHandler: Error deleting old refresh token for username: %s, err: %v", u.Username, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		s.writeJsonResponse(w, response{AccessToken: at, RefreshToken: newRT, RefreshTokenID: newRTID}, http.StatusOK)
	}
}

// Returns access token, refresh token, refresh token ID, and error
func (s Server) issueNewAccessAndRefreshToken(ctx context.Context, u database.User) (string, string, string, error) {
	rt, rtHash, rtExp, err := s.createRefreshToken(u.ID.Hex())
	if err != nil {
		return "", "", "", err
	}
	at, err := s.createAccessToken(u.ID.Hex(), u.Role)
	if err != nil {
		return "", "", "", err
	}

	// Only store hashed refresh token
	rtID, err := s.AuthDB.InsertRefreshToken(ctx, database.RefreshToken{
		UserID:     u.ID,
		Token:      rtHash,
		Expiration: primitive.NewDateTimeFromTime(rtExp),
	})
	if err != nil {
		return "", "", "", err
	}

	return at, rt, rtID, nil
}

// Returns refresh token, bcrypt refresh token hash, refresh token expiration time, and error
func (s Server) createRefreshToken(userID string) (string, []byte, time.Time, error) {
	refreshExp := time.Now().AddDate(0, 0, 90)
	refreshJWT, err := jwt.NewBuilder().
		Subject(userID).
		Issuer("go-demo-auth-service").
		Expiration(refreshExp).
		Claim("type", "refresh-token").
		Build()
	if err != nil {
		return "", nil, refreshExp, fmt.Errorf("error creating refresh token: %w", err)
	}
	rt, err := jwt.Sign(refreshJWT, jwt.WithKey(jwa.HS256, s.RefreshTokenSecret))
	if err != nil {
		return "", nil, refreshExp, fmt.Errorf("error signing refresh token: %w", err)
	}

	// Hash refresh token with sha256 before bcrypt because bcrypt has max password length of 72 bytes
	refreshTokenHash := sha256.New()
	refreshTokenHash.Write(rt)
	bcryptTokenHash, err := bcrypt.GenerateFromPassword(refreshTokenHash.Sum(nil), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, refreshExp, fmt.Errorf("error generating bcrypt from refresh token hash: %w", err)
	}

	return string(rt), bcryptTokenHash, refreshExp, nil
}

// Returns access token and error
func (s Server) createAccessToken(userID string, role string) (string, error) {
	accessExp := time.Now().Add(10 * time.Minute)
	accessJWT, err := jwt.NewBuilder().
		Subject(userID).
		Issuer("go-demo-auth-service").
		Expiration(accessExp).
		Claim("type", "access-token").
		Claim("role", role).
		Build()
	if err != nil {
		return "", fmt.Errorf("error creating access token: %w", err)
	}
	at, err := jwt.Sign(accessJWT, jwt.WithKey(jwa.HS256, s.AccessTokenSecret))
	if err != nil {
		return "", fmt.Errorf("error signing access token: %w", err)
	}

	return string(at), nil
}

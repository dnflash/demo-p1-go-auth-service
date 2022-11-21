package server

import (
	"encoding/json"
	"github.com/dnflash/demo-p1-go-auth-service/internal/database"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"log"
	"net/http"
)

type Server struct {
	AuthDB             database.AuthDatabase
	UserDB             database.UserDatabase
	AccessTokenSecret  jwk.Key
	RefreshTokenSecret jwk.Key
}

func (s Server) writeJsonResponse(w http.ResponseWriter, response any, statusCode int) {
	if resp, err := json.Marshal(response); err != nil {
		log.Printf("Error encoding response: %+v, err: %v", response, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(statusCode)
		if _, err = w.Write(resp); err != nil {
			log.Printf("Error writing JSON response: %s, err: %v", resp, err)
		}
	}
}

package server

import (
	"github.com/gorilla/mux"
	"net/http"
)

func (s Server) Router() *mux.Router {
	r := mux.NewRouter()

	r.PathPrefix("/docs").Handler(http.StripPrefix("/docs", http.FileServer(http.Dir("docs"))))

	r.HandleFunc("/login", s.loginHandler()).Methods(http.MethodPost)
	r.HandleFunc("/refresh", s.refreshHandler()).Methods(http.MethodPost)

	return r
}

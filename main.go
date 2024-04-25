package main

import (
	"net/http"
)

func main() {
    mux := http.NewServeMux()
    corsMux := middlewareCors(mux)

    mux.Handle("/app/*", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        w.WriteHeader(200)
        w.Write([]byte("OK"))
    }) 

    server := http.Server{
        Addr: "localhost:3005",
        Handler: corsMux,
    }

    server.ListenAndServe()
}

func middlewareCors(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Headers", "*")
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")

        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    })
}

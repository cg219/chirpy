package main

import (
	"net/http"
	"os"
)

func main() {
    mux := http.NewServeMux()
    corsMux := middlewareCors(mux)

    server := http.Server{
        Addr: "localhost:3005",
        Handler: corsMux,
    }

    err := server.ListenAndServe()

    if err != nil {
        os.Exit(0)
    }
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

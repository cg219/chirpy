package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cg219/chirpy/internal/database"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
)

type apistate struct {
    fileserverHits int
    jwtsecret string
}

func (c *apistate) middlewareMetrics(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    fmt.Println(*c)
        c.fileserverHits += 1

        next.ServeHTTP(w, r)
    })
}

func (c *apistate) middlewareMetricsReset(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        c.fileserverHits = 0

        next.ServeHTTP(w, r)
    })
}

func (c *apistate) handleMetrics(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.WriteHeader(200)
    w.Write([]byte(fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", c.fileserverHits)))
}

func handleGetChirps(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    type errorResp struct {
        Error string `json:"error"`
    }

    db, err := database.NewDB("database.json")

    e := errorResp{}

    if err != nil {
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    chirps, err := db.GetChirps()

    if err != nil {
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    res, _ := json.Marshal(chirps)
    w.WriteHeader(200)
    w.Write(res)
}

func handleGetOneChirp(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    type errorResp struct {
        Error string `json:"error"`
    }

    db, err := database.NewDB("database.json")

    e := errorResp{}

    if err != nil {
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    rawID := r.PathValue("chirpID")
    id, err := strconv.Atoi(rawID)

    if err != nil {
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    chirp, err := db.GetChirp(id)

    if err != nil {
        e.Error = "Chirp not found"
        res, _ := json.Marshal(e)    
        w.WriteHeader(404)
        w.Write(res)
        return
    }

    res, _ := json.Marshal(chirp)
    w.WriteHeader(200)
    w.Write(res)

}

func (c *apistate) handleLogin(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    type body struct {
        Email string `json:"email"`
        Password string `json:"password"`
        Expires int `json:"expires_in_seconds"`
    }

    type errorResp struct {
        Error string `json:"error"`
    }

    type response struct {
        Id int `json:"id"`
        Email string `json:"email"`
        Token string `json:"token"`
    }

    decoder := json.NewDecoder(r.Body)
    b := body{}
    e := errorResp{}
    err := decoder.Decode(&b)

    if err != nil {
        log.Print("Error Decoding JSON")
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    db, err := database.NewDB("database.json")

    if err != nil {
        log.Print(err)
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    user, err := db.GetUser(b.Email, b.Password)

    if err != nil {
        log.Print(err)
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(401)
        w.Write(res)
        return
    }

    expiresIn := 86400
    secretkey := []byte(c.jwtsecret)
    
    if b.Expires > 0 && b.Expires < expiresIn {
        expiresIn = b.Expires
    }
    
    now := time.Now()
    claims := &jwt.RegisteredClaims {
        IssuedAt: jwt.NewNumericDate(now.UTC()),
        ExpiresAt: jwt.NewNumericDate(now.Add(time.Second * time.Duration(expiresIn)).UTC()),
        Issuer: "chirpy",
        Subject: strconv.Itoa(user.ID),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    ss, _ := token.SignedString(secretkey)

    tokenResp := response{
        Id: user.ID,
        Email: user.Email,
        Token: ss,
    }

    res, _ := json.Marshal(tokenResp)
    w.WriteHeader(200)
    w.Write(res)
    return
}

func (c *apistate) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
    type body struct {
        Email string `json:"email"`
        Password string `json:"password"`
    }

    type errorResp struct {
        Error string `json:"error"`
    }

    tokenstring := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    decoder := json.NewDecoder(r.Body)
    b := body{}
    e := errorResp{}
    err := decoder.Decode(&b)

    if err != nil {
        log.Print("Error Decoding JSON")
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    token, err := jwt.ParseWithClaims(tokenstring, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
        return []byte(c.jwtsecret), nil
    })

    fmt.Printf("Token: %v\n", token)

    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        w.Write([]byte("Not Allowed"))
    } else if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok {
        userid, _ := strconv.Atoi(claims.Subject)

        db, err := database.NewDB("database.json")

        if err != nil {
            log.Print(err)
            e.Error = "Something went wrong"
            res, _ := json.Marshal(e)    
            w.WriteHeader(500)
            w.Write(res)
            return
        }

        cu, err := db.UpdateUser(database.User{ ID: userid, Email: b.Email, Password: []byte(b.Password) })

        if err != nil {
            log.Print(err)
            e.Error = "Something went wrong"
            res, _ := json.Marshal(e)    
            w.WriteHeader(500)
            w.Write(res)
            return
        }

        res, _ := json.Marshal(cu)
        w.WriteHeader(http.StatusOK)
        w.Write(res)
    }
     
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    type body struct {
        Email string `json:"email"`
        Password string `json:"password"`
    }

    type errorResp struct {
        Error string `json:"error"`
    }

    decoder := json.NewDecoder(r.Body)
    b := body{}
    e := errorResp{}
    err := decoder.Decode(&b)

    if err != nil {
        log.Print("Error Decoding JSON")
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    db, err := database.NewDB("database.json")

    if err != nil {
        log.Print(err)
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    user, err := db.CreateUser(b.Email, b.Password)

    if err != nil {
        log.Print(err)
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    res, _ := json.Marshal(user)
    w.WriteHeader(201)
    w.Write(res)
    return
}

func handleCreateChrip(w http.ResponseWriter, r *http.Request) {
    restricted := []string{"kerfuffle", "sharbert", "fornax"}
    w.Header().Set("Content-Type", "application/json")

    type body struct {
        Body string `json:"body"`
    }

    type errorResp struct {
        Error string `json:"error"`
    }

    decoder := json.NewDecoder(r.Body)
    b := body{}
    e := errorResp{}
    err := decoder.Decode(&b)

    if err != nil {
        log.Print("Error Decoding JSON")
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    if len(b.Body) > 140 {
        e.Error = "Chirp is too long"
        res, _ := json.Marshal(e)
        w.WriteHeader(400)
        w.Write(res)
        return
    }

    cleaned := []string{}

    for _, word := range strings.Split(b.Body, " ") {
        c := word

        for _, banned := range restricted {
            if banned == strings.ToLower(word) {
                c = "****"
                break
            }
        }

        cleaned = append(cleaned, c)
    }

    db, err := database.NewDB("database.json")

    if err != nil {
        log.Print(err)
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    chirp, err := db.CreateChirp(strings.Join(cleaned, " "))

    if err != nil {
        log.Print("Error Creating CreatChirp")
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)    
        w.WriteHeader(500)
        w.Write(res)
        return
    }

    res, _ := json.Marshal(chirp)
    w.WriteHeader(201)
    w.Write(res)
    return
}

func main() {
    godotenv.Load()

    mux := http.NewServeMux()
    corsMux := middlewareCors(mux)
    apiconfig := apistate{
        fileserverHits: 0,
        jwtsecret: os.Getenv("JWT_SECRET"),
    }

    mux.Handle("/app/*", apiconfig.middlewareMetrics(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
    mux.HandleFunc("GET /admin/metrics", apiconfig.handleMetrics)
    mux.HandleFunc("POST /api/chirps", handleCreateChrip)
    mux.HandleFunc("POST /api/users", handleCreateUser)
    mux.HandleFunc("PUT /api/users", apiconfig.handleUpdateUser)
    mux.HandleFunc("POST /api/login", apiconfig.handleLogin)
    mux.HandleFunc("GET /api/chirps", handleGetChirps)
    mux.HandleFunc("GET /api/chirps/{chirpID}", handleGetOneChirp)
    mux.Handle("/api/reset", apiconfig.middlewareMetricsReset(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(200)
    })))
    mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
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

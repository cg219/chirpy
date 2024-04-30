package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func checkErrorRespose(err error, w *http.ResponseWriter) bool {
    type errorResp struct {
        Error string `json:"error"`
    }

    e := errorResp{}

    if err != nil {
        log.Print(err)
        e.Error = "Something went wrong"
        res, _ := json.Marshal(e)
        (*w).WriteHeader(500)
        (*w).Write(res)
        return false
    }

    return true
}

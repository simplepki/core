package main

import (
	"log"

	//"io/ioutil"

	"net/http"
)

func main() {

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}

	http.HandleFunc("/", handler)

	err := http.ListenAndServeTLS(":8443", "cert.pem", "cert.key", nil)
	if err != nil {
		log.Fatal(err)
	}
}

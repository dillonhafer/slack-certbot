package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
)

func DomainName(r *http.Request) string {
	rx := regexp.MustCompile("<http:\\/\\/(.*)\\|")
	match := rx.FindStringSubmatch(r.FormValue("text"))

	if len(match) > 1 {
		return match[1]
	} else {
		return "certs.hshrckt.com"
	}
}

func root(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	domain := DomainName(r)
	user := r.FormValue("user_name")

	cert := NewCert(user, domain)

	resp, err := json.Marshal(cert)
	if err != nil {
		log.Fatalf("json marshall failed: %v", err)
		w.Write([]byte("{\"text\": \"Something went wrong\"}"))
		return
	}

	w.Write(resp)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	http.HandleFunc("/", root)
	http.ListenAndServe(":"+port, nil)
}

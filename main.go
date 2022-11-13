package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

const READ_TIMEOUT = 5
const WRITE_TIMEOUT = 10

func Hello(name string) string {
	return "Hello, " + name
}

func getHello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, Hello("ambula"))
}

func main() {
	http.HandleFunc("/", getHello)

	srv := &http.Server{
		Addr:         ":1984",
		ReadTimeout:  READ_TIMEOUT * time.Second,
		WriteTimeout: WRITE_TIMEOUT * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

package main

import (
	"fmt"
	"log"
	"net/http"
)

func Hello(name string) string {
	return "Hello, " + name
}

func getHello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, Hello("ambula"))
}

func main() {
	http.HandleFunc("/", getHello)

	if err := http.ListenAndServe(":1984", nil); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

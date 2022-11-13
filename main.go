package main

import "fmt"
import "net/http"

func Hello(name string) string {
	return "Hello, " + name
}

func getHello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, Hello("ambula"))
}

func main() {
	http.HandleFunc("/", getHello)
	http.ListenAndServe(":1984", nil)
}

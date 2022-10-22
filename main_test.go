package main

import (
	"fmt"
	"testing"
)

func TestHello(t *testing.T) {
	cases := []struct {
		Name     string
		Greeting string
	}{
		{Name: "Ambula", Greeting: "Hello, Ambula"},
		{Name: "Satoshi", Greeting: "Hello, Satoshi"},
		{Name: "Vitalik", Greeting: "Hello, Vitalik"},
	}
	for _, test := range cases {
		t.Run(fmt.Sprintf("%s gets greet by %s", test.Name, test.Greeting), func(t *testing.T) {
			got := Hello(test.Name)
			if got != test.Greeting {
				t.Errorf("got %q, want %q", got, test.Greeting)
			}
		})
	}
}

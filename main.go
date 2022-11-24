package main

import (
	"fmt"
	"log"
	"time"

	"github.com/pacokleitz/ambula/network"
)

func main() {
	localAddr := network.NetAddr{Addr: "A", Net: "local"}
	remoteAddr := network.NetAddr{Addr: "B", Net: "local"}

	trLocal := network.NewLocalTransport(localAddr)
	trRemote := network.NewLocalTransport(remoteAddr)

	if err := trLocal.Connect(trRemote); err != nil {
		log.Fatal(err)
	}

	if err := trRemote.Connect(trLocal); err != nil {
		log.Fatal(err)
	}

	go func() {
		i := 0
		for {
			msg := fmt.Sprintf("hello ambula %d", i)
			if err := trRemote.SendMessage(trLocal.Addr(), []byte(msg)); err != nil {
				log.Fatal(err)
			}
			i += 1
			time.Sleep(1 * time.Second)
		}
	}()

	opts := network.NodeOpts{
		Transports: []network.Transport{trLocal},
	}

	s := network.NewNode(opts)
	if err := s.Start(); err != nil {
		log.Fatal(err)
	}
}

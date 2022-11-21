package network

type NetAddr struct {
	Addr string
	Net  string
}

func (netAddr NetAddr) Network() string {
	return netAddr.Net
}

func (netAddr NetAddr) String() string {
	return netAddr.Addr
}

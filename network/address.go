package network

type NetAddr struct {
	Addr string
	Net  string
}

func (naddr NetAddr) Network() string {
	return naddr.Net
}

func (naddr NetAddr) String() string {
	return naddr.Addr
}

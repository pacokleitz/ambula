package network

// A NetAddr is identifying a Transport.
type NetAddr struct {
	Addr string
	Net  string
}

// Network returns the Network of the NetAddr (tcp, udp, local...).
func (netAddr NetAddr) Network() string {
	return netAddr.Net
}

// String returns the Network identity address of the NetAddr (127.0.0.1, "hostname",...).
func (netAddr NetAddr) String() string {
	return netAddr.Addr
}

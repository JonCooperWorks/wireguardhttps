package wireguardhttps

import (
	"github.com/joncooperworks/wireguardrpc/pb"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
)

// Wireguard interfaces with the wgrpcd gRPC API.
type Wireguard struct {
	GrpcAddress string
	DeviceName  string
}

// connection returns a GRPC connection to ensure all gRPC connections are done in a consistent way.
// Callers of this must Close() the connection themselves.
func (w *Wireguard) connection() (*grpc.ClientConn, error) {
	return grpc.Dial(w.grpcAddress, grpc.WithInsecure(), grpc.WithBlock())
}

func (w *Wireguard) CreatePeer(allowedIPs []net.IPNet) (*PeerConfigINI, error) {
	conn, err := w.connection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := pb.NewWireguardRPCClient(conn)
	request := &pb.CreatePeerRequest{
		AllowedIPS: ipNetsToStrings(allowedIPs),
		DeviceName: w.DeviceName,
	}
	response, err := client.CreatePeer(context.Background(), request)
	if err != nil {
		return nil, err
	}
	peerConfigINI := &PeerConfigINI{
		PrivateKey: response.PrivateKey,
		PublicKey:  response.PublicKey,
		AllowedIPs: allowedIPs,
	}
	return peerConfigINI, nil
}

func (w *Wireguard) RekeyPeer(oldPublicKey wgtypes.Key, allowedIPs []net.IPNet) (*PeerConfigINI, error) {
	conn, err := w.connection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := pb.NewWireguardRPCClient(conn)
	request := &pb.RekeyPeerRequest{
		PublicKey:  oldPublicKey.String(),
		AllowedIPS: ipNetsToStrings(allowedIPs),
		DeviceName: w.DeviceName,
	}
	response, err := client.RekeyPeer(context.Background(), request)
	if err != nil {
		return nil, err
	}

	peerConfigINI := &PeerConfigINI{
		PrivateKey: response.PrivateKey,
		PublicKey:  response.PublicKey,
		AllowedIPs: allowedIPs,
	}
	return peerConfigINI, nil
}

func (w *Wireguard) ChangeListenPort(int listenPort) (int, error) {
	conn, err := w.connection()
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	client := pb.NewWireguardRPCClient(conn)
	request := &pb.ChangeListenPortRequest{
		ListenPort: listenPort,
		DeviceName: w.DeviceName,
	}
	response, err := client.ChangeListenPort(request)
	if err != nil {
		return 0, err
	}

	return response.NewListenPort, nil
}

func (w *Wireguard) RemovePeer(publicKey wgtypes.Key) (bool, error) {
	conn, err := w.connection()
	if err != nil {
		return false, err
	}
	defer conn.Close()

	client := pb.NewWireguardRPCClient(conn)
	request := &pb.RemovePeerRequest{
		PublicKey: publicKey.String(),
	}
	response, err := client.RemovePeer(request)
	if err != nil {
		return false, err
	}

	return response.Removed, nil
}

func (w *Wireguard) ListPeers() ([]*pb.Peer, error) {
	conn, err := w.connection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := pb.NewWireguardRPCClient(conn)
	request := &pb.ListPeersRequest{
		DeviceName: w.DeviceName,
	}
	response, err := client.ListPeers(request)
	if err != nil {
		return []*pb.Peer{}, err
	}

	return response.Peers, nil
}

func (w *Wireguard) Devices ([]string, error) {
	conn, err := w.connection()
	if err != nil {
		return []string{}, err
	}
	defer conn.Close()

	client := pb.NewWireguardRPCClient(conn)
	request := &pb.DevicesRequest{}
	response, err := client.Devices(request)
	if err != nil {
		[]string{}, err
	}

	return response.Devices, nil
}

func ipNetsToStrings(nets []net.IPNet) []string {
	ips := []string{}
	for _, net := range nets {
		ips = append(ips, net.String())
	}
	return ips
}

func stringsToIPNet(cidrStrings []string) ([]net.IPNet, error) {
	ipNets := []net.IPNet{}
	for _, cidr := range cidrStrings {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		ipNets = append(ipNets, *ipNet)
	}
	return ipNets, nil
}

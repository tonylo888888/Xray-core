package shadowsocks_2022

import (
	"context"
	"encoding/base64"
	"io"
	"runtime"
	"strings"
	"time"

	C "github.com/sagernet/sing/common"
	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/random"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/protocol/shadowsocks"
	"github.com/sagernet/sing/protocol/shadowsocks/shadowaead_2022"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

type Outbound struct {
	ctx    context.Context
	server net.Destination
	method shadowsocks.Method
}

func NewClient(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	o := &Outbound{
		ctx: ctx,
		server: net.Destination{
			Address: config.Address.AsAddress(),
			Port:    net.Port(config.Port),
			Network: net.Network_TCP,
		},
	}
	if C.Contains(shadowaead_2022.List, config.Method) {
		if config.Key == "" {
			return nil, newError("missing psk")
		}
		var pskList [][]byte
		for _, ks := range strings.Split(config.Key, ":") {
			psk, err := base64.StdEncoding.DecodeString(ks)
			if err != nil {
				return nil, newError("decode key ", ks).Base(err)
			}
			pskList = append(pskList, psk)
		}
		var rng io.Reader = random.Default
		if config.ReducedIvHeadEntropy {
			rng = &shadowsocks.ReducedEntropyReader{
				Reader: rng,
			}
		}
		method, err := shadowaead_2022.New(config.Method, pskList, "", rng)
		if err != nil {
			return nil, newError("create method").Base(err)
		}
		o.method = method
	} else {
		return nil, newError("unknown method ", config.Method)
	}
	return o, nil
}

func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	var inboundConn net.Conn
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inboundConn = inbound.Conn
	}

	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	/*if statConn, ok := inboundConn.(*internet.StatCounterConn); ok {
		inboundConn = statConn.Connection
	}*/
	destination := outbound.Target
	network := destination.Network

	newError("tunneling request to ", destination, " via ", o.server.NetAddr()).WriteToLog(session.ExportIDToError(ctx))

	serverDestination := o.server
	serverDestination.Network = network
	connection, err := dialer.Dial(ctx, serverDestination)
	if err != nil {
		return newError("failed to connect to server").Base(err)
	}

	if network == net.Network_TCP {
		serverConn := o.method.DialEarlyConn(connection, SingDestination(destination))
		var handshake bool
		if timeoutReader, isTimeoutReader := link.Reader.(buf.TimeoutReader); isTimeoutReader {
			mb, err := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 100)
			if err != nil && err != buf.ErrNotTimeoutReader && err != buf.ErrReadTimeout {
				return newError("read payload").Base(err)
			}
			_payload := B.StackNew()
			payload := C.Dup(_payload)
			for {
				payload.FullReset()
				nb, n := buf.SplitBytes(mb, payload.FreeBytes())
				if n > 0 {
					payload.Truncate(n)
					_, err = serverConn.Write(payload.Bytes())
					if err != nil {
						return newError("write payload").Base(err)
					}
					handshake = true
				}
				if nb.IsEmpty() {
					break
				} else {
					mb = nb
				}
			}
			runtime.KeepAlive(_payload)
		}
		if !handshake {
			_, err = serverConn.Write(nil)
			if err != nil {
				return newError("client handshake").Base(err)
			}
		}
		conn := &PipeConnWrapper{
			W:    link.Writer,
			Conn: inboundConn,
		}
		if ir, ok := link.Reader.(io.Reader); ok {
			conn.R = ir
		} else {
			conn.R = &buf.BufferedReader{Reader: link.Reader}
		}

		return rw.CopyConn(ctx, conn, serverConn)
	} else {
		var packetConn N.PacketConn
		if pc, isPacketConn := inboundConn.(N.PacketConn); isPacketConn {
			packetConn = pc
		} else if nc, isNetPacket := inboundConn.(net.PacketConn); isNetPacket {
			packetConn = &N.PacketConnWrapper{PacketConn: nc}
		} else {
			packetConn = &PacketConnWrapper{
				Reader: link.Reader,
				Writer: link.Writer,
				Conn:   inboundConn,
				Dest:   destination,
			}
		}

		serverConn := o.method.DialPacketConn(connection)
		return N.CopyPacketConn(ctx, packetConn, serverConn)
	}
}

func SingDestination(destination net.Destination) M.Socksaddr {
	var addr M.Socksaddr
	switch destination.Address.Family() {
	case net.AddressFamilyDomain:
		addr.Fqdn = destination.Address.Domain()
	default:
		addr.Addr = M.AddrFromIP(destination.Address.IP())
	}
	addr.Port = uint16(destination.Port)
	return addr
}

type PipeConnWrapper struct {
	R io.Reader
	W buf.Writer
	net.Conn
}

func (w *PipeConnWrapper) Close() error {
	common.Interrupt(w.R)
	common.Interrupt(w.W)
	common.Close(w.Conn)
	return nil
}

func (w *PipeConnWrapper) Read(b []byte) (n int, err error) {
	return w.R.Read(b)
}

func (w *PipeConnWrapper) Write(p []byte) (n int, err error) {
	n = len(p)
	var mb buf.MultiBuffer
	pLen := len(p)
	for pLen > 0 {
		buffer := buf.New()
		if pLen > buf.Size {
			_, err = buffer.Write(p[:buf.Size])
			p = p[buf.Size:]
		} else {
			buffer.Write(p)
		}
		pLen -= int(buffer.Len())
		mb = append(mb, buffer)
	}
	err = w.W.WriteMultiBuffer(mb)
	if err != nil {
		n = 0
		buf.ReleaseMulti(mb)
	}
	return
}

type PacketConnWrapper struct {
	buf.Reader
	buf.Writer
	net.Conn
	Dest   net.Destination
	cached buf.MultiBuffer
}

func (w *PacketConnWrapper) ReadPacket(buffer *B.Buffer) (M.Socksaddr, error) {
	if w.cached != nil {
		mb, bb := buf.SplitFirst(w.cached)
		if bb == nil {
			w.cached = nil
		} else {
			buffer.Write(bb.Bytes())
			w.cached = mb
			var destination net.Destination
			if bb.UDP != nil {
				destination = *bb.UDP
			} else {
				destination = w.Dest
			}
			bb.Release()
			return SingDestination(destination), nil
		}
	}
	mb, err := w.ReadMultiBuffer()
	if err != nil {
		return M.Socksaddr{}, err
	}
	nb, bb := buf.SplitFirst(mb)
	if bb == nil {
		return M.Socksaddr{}, nil
	} else {
		buffer.Write(bb.Bytes())
		w.cached = nb
		var destination net.Destination
		if bb.UDP != nil {
			destination = *bb.UDP
		} else {
			destination = w.Dest
		}
		bb.Release()
		return SingDestination(destination), nil
	}
}

func (w *PacketConnWrapper) WritePacket(buffer *B.Buffer, addrPort M.Socksaddr) error {
	vBuf := buf.New()
	vBuf.Write(buffer.Bytes())
	endpoint := net.DestinationFromAddr(addrPort.UDPAddr())
	vBuf.UDP = &endpoint
	return w.Writer.WriteMultiBuffer(buf.MultiBuffer{vBuf})
}

func (w *PacketConnWrapper) Close() error {
	common.Interrupt(w.Reader)
	common.Close(w.Conn)
	buf.ReleaseMulti(w.cached)
	return nil
}

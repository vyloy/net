package factory

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"github.com/skycoin/net/conn"
	"github.com/skycoin/net/factory"
	"github.com/skycoin/skycoin/src/cipher"
	"io"
	"net"
	"sync"
)

func init() {
	ops[OP_BUILD_APP_CONN] = &sync.Pool{
		New: func() interface{} {
			return new(appConn)
		},
	}
	ops[OP_FORWARD_NODE_CONN] = &sync.Pool{
		New: func() interface{} {
			return new(forwardNodeConn)
		},
	}
	resps[OP_BUILD_NODE_CONN] = &sync.Pool{
		New: func() interface{} {
			return new(buildConn)
		},
	}
	ops[OP_FORWARD_NODE_CONN_RESP] = &sync.Pool{
		New: func() interface{} {
			return new(forwardNodeConnResp)
		},
	}
	resps[OP_FORWARD_NODE_CONN_RESP] = &sync.Pool{
		New: func() interface{} {
			return new(forwardNodeConnResp)
		},
	}
	resps[OP_FORWARD_NODE_CONN] = &sync.Pool{
		New: func() interface{} {
			return new(buildConnResp)
		},
	}
	ops[OP_BUILD_APP_CONN_OK] = &sync.Pool{
		New: func() interface{} {
			return new(buildConnResp)
		},
	}
	resps[OP_BUILD_APP_CONN] = &sync.Pool{
		New: func() interface{} {
			return new(AppConnResp)
		},
	}
	resps[OP_APP_CONN_ACK] = &sync.Pool{
		New: func() interface{} {
			return new(connAck)
		},
	}
	ops[OP_APP_FEEDBACK] = &sync.Pool{
		New: func() interface{} {
			return new(AppFeedback)
		},
	}
	resps[OP_BUILD_APP_CONN_OK] = &sync.Pool{
		New: func() interface{} {
			return new(nop)
		},
	}
}

type appConn struct {
	Node cipher.PubKey
	App  cipher.PubKey
}

// run on node A
func (req *appConn) Execute(f *MessengerFactory, c *Connection) (r resp, err error) {
	if !f.Proxy {
		return
	}

	f.ForEachConn(func(connection *Connection) {
		fromNode := connection.GetKey()
		fromApp := c.GetKey()
		iv := make([]byte, aes.BlockSize)
		if _, err = io.ReadFull(rand.Reader, iv); err != nil {
			c.GetContextLogger().Debugf("transport err %v", err)
			return
		}
		tr := NewTransport(f, c, fromNode, req.Node, fromApp, req.App)
		tr.SetOnInitUDPCallback(func(connection *factory.Connection) {
			sc := f.GetDefaultSeedConfig()
			connection.GetContextLogger().Debugf("set crypto sc %v", sc)
			if sc == nil {
				connection.GetContextLogger().Errorf("tr sc is nil")
			}
			crypto := conn.NewCrypto(sc.secKey, req.Node, iv)
			if crypto == nil {
				connection.GetContextLogger().Error("NewCrypto return nil")
				return
			}
			connection.SetCrypto(crypto)
			if err != nil {
				connection.GetContextLogger().Errorf("set crypto err %v", err)
			}
		})
		c.GetContextLogger().Debugf("app conn create transport to %s", connection.GetRemoteAddr().String())
		trc, err := tr.ListenAndConnect(connection.GetRemoteAddr().String(), connection.GetTargetKey())
		if err != nil {
			c.GetContextLogger().Debugf("transport err %v", err)
			return
		}
		nodeConn := &forwardNodeConn{
			Node:     req.Node,
			App:      req.App,
			FromApp:  fromApp,
			FromNode: fromNode,
			Num:      iv,
		}
		trc.writeOP(OP_FORWARD_NODE_CONN, nodeConn)
		c.setTransport(req.App, tr)
		tr.SetupTimeout()
	})
	return
}

type Priority int
type MsgType int

const (
	Success MsgType = iota
	Failed
)

const (
	_ Priority = iota
	Building
	Connected
	NotFound
	NotAllowed
	Timeout
	TransportClosed
)

type PriorityMsg struct {
	Priority Priority `json:"priority"`
	Msg      string   `json:"msg"`
	Type     MsgType  `json:"type"`
	Time     int64    `json:"time"`
}

type AppConnResp struct {
	App    cipher.PubKey
	Host   string `json:",omitempty"`
	Port   int
	Failed bool
	Msg    PriorityMsg
}

// run on app
func (req *AppConnResp) Run(conn *Connection) (err error) {
	conn.GetContextLogger().Debugf("recv %#v", req)
	if conn.appConnectionInitCallback != nil {
		addr := conn.GetRemoteAddr().String()
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}
		req.Host = host
		fb := conn.appConnectionInitCallback(req)
		fb.App = req.App
		err = conn.writeOP(OP_APP_FEEDBACK, fb)
	}
	return
}

type AppFeedback struct {
	// to app
	App    cipher.PubKey
	Port   int         `json:"port"`
	Failed bool        `json:"failed"`
	Msg    PriorityMsg `json:"msg"`
}

func (req *AppFeedback) Execute(f *MessengerFactory, conn *Connection) (r resp, err error) {
	conn.GetContextLogger().Debugf("recv %#v", req)
	conn.appFeedback.Store(req)
	tr, ok := conn.getTransport(req.App)
	if !ok {
		conn.GetContextLogger().Debugf("AppFeedback tr %x not found", req.App)
		return
	}
	tr.StopTimeout()
	if req.Failed {
		tr.Close()
	}
	return
}

type buildConnResp buildConn

// run on node A, conn is udp from node B
func (req *buildConnResp) Execute(f *MessengerFactory, conn *Connection) (r resp, err error) {
	conn.GetContextLogger().Debugf("buildConnResp %#v", req)
	appConn, ok := f.Parent.GetConnection(req.FromApp)
	if !ok {
		conn.GetContextLogger().Debugf("buildConnResp app %x not found", req.FromApp)
		return
	}
	tr, ok := appConn.getTransport(req.App)
	if !ok {
		conn.GetContextLogger().Debugf("buildConnResp tr %x not found", req.App)
		return
	}
	tr.setUDPConn(conn)
	fnOK := func(port int) {
		msg := fmt.Sprintf("Connected app %x", req.App)
		priorityMsg := PriorityMsg{Priority: Connected, Msg: msg}
		appConn.PutMessage(priorityMsg)
		appConn.writeOP(OP_BUILD_APP_CONN|RESP_PREFIX, &AppConnResp{
			App:  req.App,
			Port: port,
			Msg:  priorityMsg,
		})
	}
	err = tr.ListenForApp(fnOK)
	if err != nil {
		conn.GetContextLogger().Debugf("ListenForApp err %v", err)
		return
	}
	tr.connAck()
	err = conn.writeOP(OP_APP_CONN_ACK|RESP_PREFIX, &connAck{
		FromApp: req.FromApp,
		App:     req.App,
	})
	if err != nil {
		conn.GetContextLogger().Debugf("buildConnResp err %v", err)
		return
	}
	conn.GetContextLogger().Debugf("buildConnResp detach")
	err = ErrDetach
	return
}

// run on node A, from manager udp
func (req *buildConnResp) Run(conn *Connection) (err error) {
	tr, ok := conn.getTransport(req.App)
	if !ok {
		conn.GetContextLogger().Debugf("buildConnResp run tr %#v not found", req)
		return
	}
	conn.GetContextLogger().Debugf("recv %#v tr %#v", req, tr)
	return
}

type forwardNodeConn struct {
	Node     cipher.PubKey
	App      cipher.PubKey
	FromApp  cipher.PubKey
	FromNode cipher.PubKey
	Num      []byte
}

// run on manager, conn is udp conn from node A
func (req *forwardNodeConn) Execute(f *MessengerFactory, conn *Connection) (r resp, err error) {
	c, ok := f.GetConnection(req.Node)
	if !ok {
		cause := fmt.Sprintf("Node %x not exists", req.Node)
		conn.GetContextLogger().Debugf(cause)
		err = conn.writeOP(OP_FORWARD_NODE_CONN_RESP|RESP_PREFIX, &forwardNodeConnResp{
			Node:     req.Node,
			App:      req.App,
			FromApp:  req.FromApp,
			FromNode: req.FromNode,
			Failed:   true,
			Msg:      PriorityMsg{Priority: NotFound, Msg: cause, Type: Failed},
			Num:      req.Num,
		})
		return
	}

	conn.GetContextLogger().Debugf("conn remote addr %v", conn.GetRemoteAddr())
	err = c.writeOP(OP_BUILD_NODE_CONN|RESP_PREFIX,
		&buildConn{
			Address:  conn.GetRemoteAddr().String(),
			Node:     req.Node,
			App:      req.App,
			FromApp:  req.FromApp,
			FromNode: req.FromNode,
			Num:      req.Num,
		})
	return
}

type forwardNodeConnResp struct {
	Node     cipher.PubKey
	App      cipher.PubKey
	FromApp  cipher.PubKey
	FromNode cipher.PubKey
	Failed   bool
	Msg      PriorityMsg
	Address  string
	Num      []byte
}

// run on manager, conn is tcp/udp from node B
func (req *forwardNodeConnResp) Execute(f *MessengerFactory, conn *Connection) (r resp, err error) {
	c, ok := f.GetConnection(req.FromNode)
	if !ok {
		conn.GetContextLogger().Debugf("node %x not exists", req.FromNode)
		return
	}

	req.Address = conn.GetRemoteAddr().String()
	err = c.writeOP(OP_FORWARD_NODE_CONN_RESP|RESP_PREFIX, req)
	return
}

// run on node A, from manager
func (req *forwardNodeConnResp) Run(conn *Connection) (err error) {
	appConn, ok := conn.factory.GetConnection(req.FromApp)
	if !ok {
		conn.GetContextLogger().Debugf("forwardNodeConnResp app %x not found", req.FromApp)
		return
	}
	appConn.PutMessage(req.Msg)
	tr, ok := appConn.getTransport(req.App)
	if !ok {
		conn.GetContextLogger().Debugf("forwardNodeConnResp tr %s not found", req.App.Hex())
		return
	}
	if req.Failed {
		appConn.writeOP(OP_BUILD_APP_CONN|RESP_PREFIX, &AppConnResp{
			App:    req.App,
			Failed: req.Failed,
			Msg:    req.Msg,
		})
		tr.Close()
		appConn.setTransport(req.App, nil)
		return
	}
	if len(req.Address) > 0 {
		e := tr.clientSideConnect(req.Address, conn.factory.GetDefaultSeedConfig(), req.Num)
		if e != nil {
			conn.GetContextLogger().Debugf("forwardNodeConnResp clientSideConnect %v", e)
		}
	}
	return
}

type buildConn struct {
	Address  string
	Node     cipher.PubKey
	App      cipher.PubKey
	FromApp  cipher.PubKey
	FromNode cipher.PubKey
	Num      []byte
}

func (req *buildConn) Run(conn *Connection) (err error) {
	appConn, ok := conn.factory.GetConnection(req.App)
	if !ok {
		cause := fmt.Sprintf("Node %x app %x not exists", req.Node, req.App)
		conn.GetContextLogger().Debugf(cause)
		err = conn.writeOP(OP_FORWARD_NODE_CONN_RESP, &forwardNodeConnResp{
			Node:     req.Node,
			App:      req.App,
			FromApp:  req.FromApp,
			FromNode: req.FromNode,
			Failed:   true,
			Msg:      PriorityMsg{Priority: NotFound, Msg: cause, Type: Failed},
			Num:      req.Num,
		})
		return
	}

	s, ok := appConn.getService(req.App)
	if !ok {
		cause := fmt.Sprintf("Node %x app %x not exists", req.Node, req.App)
		conn.GetContextLogger().Debugf(cause)
		err = conn.writeOP(OP_FORWARD_NODE_CONN_RESP, &forwardNodeConnResp{
			Node:     req.Node,
			App:      req.App,
			FromApp:  req.FromApp,
			FromNode: req.FromNode,
			Failed:   true,
			Msg:      PriorityMsg{Priority: NotFound, Msg: cause, Type: Failed},
			Num:      req.Num,
		})
		return
	}

	if len(s.AllowNodes) > 0 {
		allow := false
		for _, k := range s.AllowNodes {
			if k == req.FromNode.Hex() {
				allow = true
				break
			}
		}
		if !allow {
			cause := fmt.Sprintf("Node %x app %x forbid %x", req.Node, req.App, req.FromNode)
			conn.GetContextLogger().Debugf(cause)
			err = conn.writeOP(OP_FORWARD_NODE_CONN_RESP, &forwardNodeConnResp{
				Node:     req.Node,
				App:      req.App,
				FromApp:  req.FromApp,
				FromNode: req.FromNode,
				Failed:   true,
				Msg:      PriorityMsg{Priority: NotAllowed, Msg: cause, Type: Failed},
				Num:      req.Num,
			})
			return
		}
	}

	tr := NewTransport(conn.factory, appConn, req.FromNode, req.Node, req.FromApp, req.App)
	connection, err := tr.ListenAndConnect(conn.GetRemoteAddr().String(), conn.GetTargetKey())
	if err != nil {
		return
	}
	err = connection.writeOP(OP_FORWARD_NODE_CONN_RESP, &forwardNodeConnResp{
		Node:     req.Node,
		App:      req.App,
		FromApp:  req.FromApp,
		FromNode: req.FromNode,
		Msg:      PriorityMsg{Priority: Building, Msg: "Building connection"},
		Num:      req.Num,
	})
	if err != nil {
		return
	}
	err = tr.serverSiceConnect(req.Address, s.Address, conn.factory.GetDefaultSeedConfig(), req.Num)
	appConn.setTransport(req.FromApp, tr)
	tr.SetupTimeout()
	return
}

type connAck struct {
	FromApp, App cipher.PubKey
}

// run on node b from node a udp
func (req *connAck) Run(conn *Connection) (err error) {
	conn.GetContextLogger().Debugf("recv conn ack %s", req.App.Hex())
	appConn, ok := conn.factory.GetConnection(req.App)
	if !ok {
		conn.GetContextLogger().Debugf("app %x not exists", req.App)
		return
	}
	tr, ok := appConn.getTransport(req.FromApp)
	if !ok {
		conn.GetContextLogger().Debugf("tr %x not exists", tr)
		return
	}
	tr.StopTimeout()
	err = ErrDetach
	return
}

type nop struct {
}

// run on node b from node a udp
func (req *nop) Run(conn *Connection) (err error) {
	return
}

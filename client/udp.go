package client

import (
	"bytes"
	"time"
	"net"
	"github.com/skycoin/net/conn"
	"github.com/skycoin/net/msg"
	"log"
	"encoding/binary"
	"github.com/skycoin/skycoin/src/cipher"
)

type ClientUDPConn struct {
	conn.UDPConn
}

func NewClientUDPConn(c *net.UDPConn) *ClientUDPConn {
	return &ClientUDPConn{conn.UDPConn{UdpConn: c, In: make(chan []byte), Out: make(chan []byte), PendingMap: conn.PendingMap{Pending: make(map[uint32]*msg.Message)}}}
}

func (c *ClientUDPConn) ReadLoop() error {
	for {
		maxBuf := make([]byte, conn.MAX_UDP_PACKAGE_SIZE)
		n, err := c.UdpConn.Read(maxBuf)
		if err != nil {
			return err
		}
		maxBuf = maxBuf[:n]

		switch maxBuf[msg.MSG_TYPE_BEGIN] {
		case msg.TYPE_PONG:
		case msg.TYPE_ACK:
			seq := binary.BigEndian.Uint32(maxBuf[msg.MSG_SEQ_BEGIN:msg.MSG_SEQ_END])
			c.DelMsgToPendingMap(seq)
		case msg.TYPE_NORMAL:
			seq := binary.BigEndian.Uint32(maxBuf[msg.MSG_SEQ_BEGIN:msg.MSG_SEQ_END])
			err = c.Ack(seq)
			if err != nil {
				return err
			}
			c.In <- maxBuf[msg.MSG_HEADER_END:]
		}
	}
	return nil
}

const (
	TICK_PERIOD = 60
)

func (c *ClientUDPConn) ping() error {
	b := make([]byte, msg.MSG_TYPE_SIZE)
	b[msg.MSG_TYPE_BEGIN] = msg.TYPE_PING
	return c.WriteBytes(b)
}

func (c *ClientUDPConn) WriteLoop() error {
	ticker := time.NewTicker(time.Second * TICK_PERIOD)
	defer func() {
		ticker.Stop()
	}()

	for {
		select {
		case <-ticker.C:
			log.Println("Ping out")
			err := c.ping()
			if err != nil {
				return err
			}
		case m, ok := <-c.Out:
			if !ok {
				log.Println("udp conn closed")
				return nil
			}
			log.Printf("msg out %x", m)
			err := c.Write(m)
			if err != nil {
				log.Printf("write msg is failed %v", err)
				return err
			}
		}
	}
}

func (c *ClientUDPConn) Write(bytes []byte) error {
	new := c.GetNextSeq()
	m := msg.New(msg.TYPE_NORMAL, new, bytes)
	c.AddMsgToPendingMap(new, m)
	return c.WriteBytes(m.Bytes())
}

func (c *ClientUDPConn) WriteSlice(src ...[]byte) error {
	new := c.GetNextSeq()
	r := &bytes.Buffer{}
	for _, b := range src {
		r.Write(b)
	}
	m := msg.New(msg.TYPE_NORMAL, new, r.Bytes())
	c.AddMsgToPendingMap(new, m)
	return c.WriteBytes(m.Bytes())
}

func (c *ClientUDPConn) WriteBytes(bytes []byte) error {
	_, err := c.UdpConn.Write(bytes)
	return err
}

func (c *ClientUDPConn) Ack(seq uint32) error {
	resp := make([]byte, msg.MSG_SEQ_END)
	resp[msg.MSG_TYPE_BEGIN] = msg.TYPE_ACK
	binary.BigEndian.PutUint32(resp[msg.MSG_SEQ_BEGIN:], seq)
	return c.WriteBytes(resp)
}

func (c *ClientUDPConn) SendReg(key cipher.PubKey) error {
	new := c.GetNextSeq()
	m := msg.New(msg.TYPE_REG, new, key[:])
	c.AddMsgToPendingMap(new, m)
	return c.WriteBytes(m.Bytes())
}
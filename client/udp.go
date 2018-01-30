package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net"

	"github.com/skycoin/net/conn"
	"github.com/skycoin/net/msg"
)

type ClientUDPConn struct {
	*conn.UDPConn
}

func NewClientUDPConn(c *net.UDPConn, addr *net.UDPAddr) *ClientUDPConn {
	uc := conn.NewUDPConn(c, addr)
	uc.SendPing = true
	uc.UnsharedUdpConn = true
	return &ClientUDPConn{UDPConn: uc}
}

func (c *ClientUDPConn) ReadLoop() (err error) {
	defer func() {
		if !conn.DEV {
			if e := recover(); e != nil {
				c.GetContextLogger().Debug(e)
				err = fmt.Errorf("readloop panic err:%v", e)
			}
		}
		if err != nil {
			c.SetStatusToError(err)
		}
		c.Close()
	}()
	maxBuf := make([]byte, conn.MTU)
	for {
		var n int
		n, err = c.UdpConn.Read(maxBuf)
		if err != nil {
			return
		}
		c.AddReceivedBytes(n)
		pkg := maxBuf[:n]
		m := pkg[msg.PKG_HEADER_SIZE:]
		crypto := c.GetCrypto()
		if crypto != nil {
			crypto.DecryptBlock(m[0:16])
		}

		t := m[msg.MSG_TYPE_BEGIN]
		if t&0x80 > 0 {
			checksum := binary.BigEndian.Uint32(pkg[msg.PKG_CRC32_BEGIN:])
			if checksum != crc32.ChecksumIEEE(m) {
				c.GetContextLogger().Infof("checksum !=")
				continue
			}
		}
		switch t {
		case msg.TYPE_PONG:
		case msg.TYPE_ACK:
			err = c.RecvAck(m)
			if err != nil {
				return
			}
		case msg.TYPE_NORMAL, msg.TYPE_FEC, msg.TYPE_SYN:
			if crypto != nil {
				crypto.DecryptBlock(m[16:32])
			}
			checksum := binary.BigEndian.Uint32(pkg[msg.PKG_CRC32_BEGIN:])
			if checksum != crc32.ChecksumIEEE(m) {
				return errors.New("checksum !=")
			}
			err = c.Process(t, m)
			if err != nil {
				return
			}
		case msg.TYPE_FIN:
			err = conn.ErrFin
			break
		default:
			c.GetContextLogger().Debugf("not implemented msg type %d", t)
			err = fmt.Errorf("not implemented msg type %d", t)
			return
		}
		c.UpdateLastTime()
	}
}

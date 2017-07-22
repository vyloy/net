package msg

const (
	MSG_TYPE_SIZE = 1
	MSG_SEQ_SIZE  = 4
	MSG_LEN_SIZE  = 4
)

const (
	MSG_HEADER_BEGIN = 0
	MSG_TYPE_BEGIN
	MSG_TYPE_END = MSG_TYPE_BEGIN + MSG_TYPE_SIZE
	MSG_SEQ_BEGIN
	MSG_SEQ_END = MSG_SEQ_BEGIN + MSG_SEQ_SIZE
	MSG_LEN_BEGIN
	MSG_LEN_END = MSG_LEN_BEGIN + MSG_LEN_SIZE
	MSG_HEADER_END

	MSG_HEADER_SIZE
)

const (
	TYPE_NORMAL = 0x01
	TYPE_ACK    = 0x80
	TYPE_PING   = 0x81
	TYPE_PONG   = 0x82
)

const (
	MSG_STATUS_INIT = 1 << iota
	MSG_STATUS_TRANSMITTED
	MSG_STATUS_ACKED
)

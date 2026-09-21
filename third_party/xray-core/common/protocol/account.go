package protocol

import "google.golang.org/protobuf/proto"

type Account interface {
	Equals(Account) bool
	ToProto() proto.Message
}

type AsAccount interface {
	AsAccount() (Account, error)
}

package shadowsocks_2022

import (
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/protocol"
)

type MemoryAccount struct {
	Key string
}

func (u *Account) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{
		Key: u.GetKey(),
	}, nil
}

func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if account, ok := another.(*MemoryAccount); ok {
		return a.Key == account.Key
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Key: a.Key,
	}
}

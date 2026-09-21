package commander

import (
	"context"

	"github.com/xtls/xray-core/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Service interface {
	Register(*grpc.Server)
}

type reflectionService struct{}

func (r reflectionService) Register(s *grpc.Server) {
	reflection.Register(s)
}

func init() {
	common.Must(common.RegisterConfig((*ReflectionConfig)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return reflectionService{}, nil
	}))
}

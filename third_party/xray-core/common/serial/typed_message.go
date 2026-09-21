package serial

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

func ToTypedMessage(message proto.Message) *TypedMessage {
	if message == nil {
		return nil
	}
	settings, _ := proto.Marshal(message)
	return &TypedMessage{
		Type:  GetMessageType(message),
		Value: settings,
	}
}

func GetMessageType(message proto.Message) string {
	return string(message.ProtoReflect().Descriptor().FullName())
}

func GetInstance(messageType string) (interface{}, error) {
	messageTypeDescriptor := protoreflect.FullName(messageType)
	mType, err := protoregistry.GlobalTypes.FindMessageByName(messageTypeDescriptor)
	if err != nil {
		return nil, err
	}
	return mType.New().Interface(), nil
}

func (v *TypedMessage) GetInstance() (proto.Message, error) {
	instance, err := GetInstance(v.Type)
	if err != nil {
		return nil, err
	}
	protoMessage := instance.(proto.Message)
	if err := proto.Unmarshal(v.Value, protoMessage); err != nil {
		return nil, err
	}
	return protoMessage, nil
}

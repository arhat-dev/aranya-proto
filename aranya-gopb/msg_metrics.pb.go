// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: msg_metrics.proto

// +build !nometrics

package aranyagopb

import (
	bytes "bytes"
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strconv "strconv"
	strings "strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type Metrics_Kind int32

const (
	_INVALID_METRICS_KIND Metrics_Kind = 0
	// node-exporter metrics
	METRICS_NODE Metrics_Kind = 1
	// cAdvisor metrics
	METRICS_CONTAINER Metrics_Kind = 2
	// metrics collection configuration applied
	METRICS_COLLECTION_CONFIGURED Metrics_Kind = 3
)

var Metrics_Kind_name = map[int32]string{
	0: "_INVALID_METRICS_KIND",
	1: "METRICS_NODE",
	2: "METRICS_CONTAINER",
	3: "METRICS_COLLECTION_CONFIGURED",
}

var Metrics_Kind_value = map[string]int32{
	"_INVALID_METRICS_KIND":         0,
	"METRICS_NODE":                  1,
	"METRICS_CONTAINER":             2,
	"METRICS_COLLECTION_CONFIGURED": 3,
}

func (Metrics_Kind) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_65023ce91bacc04c, []int{0, 0}
}

type Metrics struct {
	Kind Metrics_Kind `protobuf:"varint,1,opt,name=kind,proto3,enum=aranya.Metrics_Kind" json:"kind,omitempty"`
	Data []byte       `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *Metrics) Reset()      { *m = Metrics{} }
func (*Metrics) ProtoMessage() {}
func (*Metrics) Descriptor() ([]byte, []int) {
	return fileDescriptor_65023ce91bacc04c, []int{0}
}
func (m *Metrics) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Metrics) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Metrics.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Metrics) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Metrics.Merge(m, src)
}
func (m *Metrics) XXX_Size() int {
	return m.Size()
}
func (m *Metrics) XXX_DiscardUnknown() {
	xxx_messageInfo_Metrics.DiscardUnknown(m)
}

var xxx_messageInfo_Metrics proto.InternalMessageInfo

func (m *Metrics) GetKind() Metrics_Kind {
	if m != nil {
		return m.Kind
	}
	return _INVALID_METRICS_KIND
}

func (m *Metrics) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func init() {
	proto.RegisterEnum("aranya.Metrics_Kind", Metrics_Kind_name, Metrics_Kind_value)
	proto.RegisterType((*Metrics)(nil), "aranya.Metrics")
}

func init() { proto.RegisterFile("msg_metrics.proto", fileDescriptor_65023ce91bacc04c) }

var fileDescriptor_65023ce91bacc04c = []byte{
	// 278 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0xcc, 0x2d, 0x4e, 0x8f,
	0xcf, 0x4d, 0x2d, 0x29, 0xca, 0x4c, 0x2e, 0xd6, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x4b,
	0x2c, 0x4a, 0xcc, 0xab, 0x4c, 0x54, 0xda, 0xc6, 0xc8, 0xc5, 0xee, 0x0b, 0x91, 0x11, 0xd2, 0xe0,
	0x62, 0xc9, 0xce, 0xcc, 0x4b, 0x91, 0x60, 0x54, 0x60, 0xd4, 0xe0, 0x33, 0x12, 0xd1, 0x83, 0x28,
	0xd1, 0x83, 0x4a, 0xeb, 0x79, 0x67, 0xe6, 0xa5, 0x04, 0x81, 0x55, 0x08, 0x09, 0x71, 0xb1, 0xa4,
	0x24, 0x96, 0x24, 0x4a, 0x30, 0x29, 0x30, 0x6a, 0xf0, 0x04, 0x81, 0xd9, 0x4a, 0xb9, 0x5c, 0x2c,
	0x20, 0x15, 0x42, 0x92, 0x5c, 0xa2, 0xf1, 0x9e, 0x7e, 0x61, 0x8e, 0x3e, 0x9e, 0x2e, 0xf1, 0xbe,
	0xae, 0x21, 0x41, 0x9e, 0xce, 0xc1, 0xf1, 0xde, 0x9e, 0x7e, 0x2e, 0x02, 0x0c, 0x42, 0x02, 0x5c,
	0x3c, 0x30, 0x11, 0x3f, 0x7f, 0x17, 0x57, 0x01, 0x46, 0x21, 0x51, 0x2e, 0x41, 0x98, 0x88, 0xb3,
	0xbf, 0x5f, 0x88, 0xa3, 0xa7, 0x9f, 0x6b, 0x90, 0x00, 0x93, 0x90, 0x22, 0x97, 0x2c, 0x42, 0xd8,
	0xc7, 0xc7, 0xd5, 0x39, 0xc4, 0xd3, 0xdf, 0x0f, 0xa4, 0xc2, 0xcd, 0xd3, 0x3d, 0x34, 0xc8, 0xd5,
	0x45, 0x80, 0xd9, 0x29, 0xfc, 0xc2, 0x43, 0x39, 0x86, 0x1b, 0x0f, 0xe5, 0x18, 0x3e, 0x3c, 0x94,
	0x63, 0x6c, 0x78, 0x24, 0xc7, 0xb8, 0xe2, 0x91, 0x1c, 0xe3, 0x89, 0x47, 0x72, 0x8c, 0x17, 0x1e,
	0xc9, 0x31, 0x3e, 0x78, 0x24, 0xc7, 0xf8, 0xe2, 0x91, 0x1c, 0xc3, 0x87, 0x47, 0x72, 0x8c, 0x13,
	0x1e, 0xcb, 0x31, 0x5c, 0x78, 0x2c, 0xc7, 0x70, 0xe3, 0xb1, 0x1c, 0x43, 0x94, 0x62, 0x62, 0x51,
	0x46, 0x62, 0x89, 0x5e, 0x4a, 0x6a, 0x99, 0x3e, 0xc4, 0x77, 0xba, 0xe0, 0xe0, 0x80, 0x72, 0xd2,
	0xf3, 0x0b, 0x92, 0x92, 0xd8, 0xc0, 0x22, 0xc6, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0x9c, 0x3d,
	0x91, 0xa0, 0x35, 0x01, 0x00, 0x00,
}

func (x Metrics_Kind) String() string {
	s, ok := Metrics_Kind_name[int32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
}
func (this *Metrics) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*Metrics)
	if !ok {
		that2, ok := that.(Metrics)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.Kind != that1.Kind {
		return false
	}
	if !bytes.Equal(this.Data, that1.Data) {
		return false
	}
	return true
}
func (this *Metrics) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 6)
	s = append(s, "&aranyagopb.Metrics{")
	s = append(s, "Kind: "+fmt.Sprintf("%#v", this.Kind)+",\n")
	s = append(s, "Data: "+fmt.Sprintf("%#v", this.Data)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringMsgMetrics(v interface{}, typ string) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("func(v %v) *%v { return &v } ( %#v )", typ, typ, pv)
}
func (m *Metrics) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Metrics) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Metrics) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Data) > 0 {
		i -= len(m.Data)
		copy(dAtA[i:], m.Data)
		i = encodeVarintMsgMetrics(dAtA, i, uint64(len(m.Data)))
		i--
		dAtA[i] = 0x12
	}
	if m.Kind != 0 {
		i = encodeVarintMsgMetrics(dAtA, i, uint64(m.Kind))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintMsgMetrics(dAtA []byte, offset int, v uint64) int {
	offset -= sovMsgMetrics(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Metrics) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Kind != 0 {
		n += 1 + sovMsgMetrics(uint64(m.Kind))
	}
	l = len(m.Data)
	if l > 0 {
		n += 1 + l + sovMsgMetrics(uint64(l))
	}
	return n
}

func sovMsgMetrics(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozMsgMetrics(x uint64) (n int) {
	return sovMsgMetrics(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *Metrics) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Metrics{`,
		`Kind:` + fmt.Sprintf("%v", this.Kind) + `,`,
		`Data:` + fmt.Sprintf("%v", this.Data) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringMsgMetrics(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *Metrics) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMsgMetrics
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Metrics: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Metrics: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Kind", wireType)
			}
			m.Kind = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMsgMetrics
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Kind |= Metrics_Kind(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Data", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMsgMetrics
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMsgMetrics
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMsgMetrics
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Data = append(m.Data[:0], dAtA[iNdEx:postIndex]...)
			if m.Data == nil {
				m.Data = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMsgMetrics(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMsgMetrics
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthMsgMetrics
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipMsgMetrics(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowMsgMetrics
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMsgMetrics
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMsgMetrics
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthMsgMetrics
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupMsgMetrics
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthMsgMetrics
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthMsgMetrics        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowMsgMetrics          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupMsgMetrics = fmt.Errorf("proto: unexpected end of group")
)

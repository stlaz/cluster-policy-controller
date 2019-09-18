// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/monitoring/v3/group_service.proto

package monitoring

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "google.golang.org/genproto/googleapis/api/annotations"
import google_api4 "google.golang.org/genproto/googleapis/api/monitoredres"
import google_protobuf4 "github.com/golang/protobuf/ptypes/empty"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// The `ListGroup` request.
type ListGroupsRequest struct {
	// The project whose groups are to be listed. The format is
	// `"projects/{project_id_or_number}"`.
	Name string `protobuf:"bytes,7,opt,name=name" json:"name,omitempty"`
	// An optional filter consisting of a single group name.  The filters limit the
	// groups returned based on their parent-child relationship with the specified
	// group. If no filter is specified, all groups are returned.
	//
	// Types that are valid to be assigned to Filter:
	//	*ListGroupsRequest_ChildrenOfGroup
	//	*ListGroupsRequest_AncestorsOfGroup
	//	*ListGroupsRequest_DescendantsOfGroup
	Filter isListGroupsRequest_Filter `protobuf_oneof:"filter"`
	// A positive number that is the maximum number of results to return.
	PageSize int32 `protobuf:"varint,5,opt,name=page_size,json=pageSize" json:"page_size,omitempty"`
	// If this field is not empty then it must contain the `nextPageToken` value
	// returned by a previous call to this method.  Using this field causes the
	// method to return additional results from the previous method call.
	PageToken string `protobuf:"bytes,6,opt,name=page_token,json=pageToken" json:"page_token,omitempty"`
}

func (m *ListGroupsRequest) Reset()                    { *m = ListGroupsRequest{} }
func (m *ListGroupsRequest) String() string            { return proto.CompactTextString(m) }
func (*ListGroupsRequest) ProtoMessage()               {}
func (*ListGroupsRequest) Descriptor() ([]byte, []int) { return fileDescriptor2, []int{0} }

type isListGroupsRequest_Filter interface {
	isListGroupsRequest_Filter()
}

type ListGroupsRequest_ChildrenOfGroup struct {
	ChildrenOfGroup string `protobuf:"bytes,2,opt,name=children_of_group,json=childrenOfGroup,oneof"`
}
type ListGroupsRequest_AncestorsOfGroup struct {
	AncestorsOfGroup string `protobuf:"bytes,3,opt,name=ancestors_of_group,json=ancestorsOfGroup,oneof"`
}
type ListGroupsRequest_DescendantsOfGroup struct {
	DescendantsOfGroup string `protobuf:"bytes,4,opt,name=descendants_of_group,json=descendantsOfGroup,oneof"`
}

func (*ListGroupsRequest_ChildrenOfGroup) isListGroupsRequest_Filter()    {}
func (*ListGroupsRequest_AncestorsOfGroup) isListGroupsRequest_Filter()   {}
func (*ListGroupsRequest_DescendantsOfGroup) isListGroupsRequest_Filter() {}

func (m *ListGroupsRequest) GetFilter() isListGroupsRequest_Filter {
	if m != nil {
		return m.Filter
	}
	return nil
}

func (m *ListGroupsRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *ListGroupsRequest) GetChildrenOfGroup() string {
	if x, ok := m.GetFilter().(*ListGroupsRequest_ChildrenOfGroup); ok {
		return x.ChildrenOfGroup
	}
	return ""
}

func (m *ListGroupsRequest) GetAncestorsOfGroup() string {
	if x, ok := m.GetFilter().(*ListGroupsRequest_AncestorsOfGroup); ok {
		return x.AncestorsOfGroup
	}
	return ""
}

func (m *ListGroupsRequest) GetDescendantsOfGroup() string {
	if x, ok := m.GetFilter().(*ListGroupsRequest_DescendantsOfGroup); ok {
		return x.DescendantsOfGroup
	}
	return ""
}

func (m *ListGroupsRequest) GetPageSize() int32 {
	if m != nil {
		return m.PageSize
	}
	return 0
}

func (m *ListGroupsRequest) GetPageToken() string {
	if m != nil {
		return m.PageToken
	}
	return ""
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*ListGroupsRequest) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _ListGroupsRequest_OneofMarshaler, _ListGroupsRequest_OneofUnmarshaler, _ListGroupsRequest_OneofSizer, []interface{}{
		(*ListGroupsRequest_ChildrenOfGroup)(nil),
		(*ListGroupsRequest_AncestorsOfGroup)(nil),
		(*ListGroupsRequest_DescendantsOfGroup)(nil),
	}
}

func _ListGroupsRequest_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*ListGroupsRequest)
	// filter
	switch x := m.Filter.(type) {
	case *ListGroupsRequest_ChildrenOfGroup:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		b.EncodeStringBytes(x.ChildrenOfGroup)
	case *ListGroupsRequest_AncestorsOfGroup:
		b.EncodeVarint(3<<3 | proto.WireBytes)
		b.EncodeStringBytes(x.AncestorsOfGroup)
	case *ListGroupsRequest_DescendantsOfGroup:
		b.EncodeVarint(4<<3 | proto.WireBytes)
		b.EncodeStringBytes(x.DescendantsOfGroup)
	case nil:
	default:
		return fmt.Errorf("ListGroupsRequest.Filter has unexpected type %T", x)
	}
	return nil
}

func _ListGroupsRequest_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*ListGroupsRequest)
	switch tag {
	case 2: // filter.children_of_group
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Filter = &ListGroupsRequest_ChildrenOfGroup{x}
		return true, err
	case 3: // filter.ancestors_of_group
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Filter = &ListGroupsRequest_AncestorsOfGroup{x}
		return true, err
	case 4: // filter.descendants_of_group
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Filter = &ListGroupsRequest_DescendantsOfGroup{x}
		return true, err
	default:
		return false, nil
	}
}

func _ListGroupsRequest_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*ListGroupsRequest)
	// filter
	switch x := m.Filter.(type) {
	case *ListGroupsRequest_ChildrenOfGroup:
		n += proto.SizeVarint(2<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.ChildrenOfGroup)))
		n += len(x.ChildrenOfGroup)
	case *ListGroupsRequest_AncestorsOfGroup:
		n += proto.SizeVarint(3<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.AncestorsOfGroup)))
		n += len(x.AncestorsOfGroup)
	case *ListGroupsRequest_DescendantsOfGroup:
		n += proto.SizeVarint(4<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.DescendantsOfGroup)))
		n += len(x.DescendantsOfGroup)
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// The `ListGroups` response.
type ListGroupsResponse struct {
	// The groups that match the specified filters.
	Group []*Group `protobuf:"bytes,1,rep,name=group" json:"group,omitempty"`
	// If there are more results than have been returned, then this field is set
	// to a non-empty value.  To see the additional results,
	// use that value as `pageToken` in the next call to this method.
	NextPageToken string `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken" json:"next_page_token,omitempty"`
}

func (m *ListGroupsResponse) Reset()                    { *m = ListGroupsResponse{} }
func (m *ListGroupsResponse) String() string            { return proto.CompactTextString(m) }
func (*ListGroupsResponse) ProtoMessage()               {}
func (*ListGroupsResponse) Descriptor() ([]byte, []int) { return fileDescriptor2, []int{1} }

func (m *ListGroupsResponse) GetGroup() []*Group {
	if m != nil {
		return m.Group
	}
	return nil
}

func (m *ListGroupsResponse) GetNextPageToken() string {
	if m != nil {
		return m.NextPageToken
	}
	return ""
}

// The `GetGroup` request.
type GetGroupRequest struct {
	// The group to retrieve. The format is
	// `"projects/{project_id_or_number}/groups/{group_id}"`.
	Name string `protobuf:"bytes,3,opt,name=name" json:"name,omitempty"`
}

func (m *GetGroupRequest) Reset()                    { *m = GetGroupRequest{} }
func (m *GetGroupRequest) String() string            { return proto.CompactTextString(m) }
func (*GetGroupRequest) ProtoMessage()               {}
func (*GetGroupRequest) Descriptor() ([]byte, []int) { return fileDescriptor2, []int{2} }

func (m *GetGroupRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

// The `CreateGroup` request.
type CreateGroupRequest struct {
	// The project in which to create the group. The format is
	// `"projects/{project_id_or_number}"`.
	Name string `protobuf:"bytes,4,opt,name=name" json:"name,omitempty"`
	// A group definition. It is an error to define the `name` field because
	// the system assigns the name.
	Group *Group `protobuf:"bytes,2,opt,name=group" json:"group,omitempty"`
	// If true, validate this request but do not create the group.
	ValidateOnly bool `protobuf:"varint,3,opt,name=validate_only,json=validateOnly" json:"validate_only,omitempty"`
}

func (m *CreateGroupRequest) Reset()                    { *m = CreateGroupRequest{} }
func (m *CreateGroupRequest) String() string            { return proto.CompactTextString(m) }
func (*CreateGroupRequest) ProtoMessage()               {}
func (*CreateGroupRequest) Descriptor() ([]byte, []int) { return fileDescriptor2, []int{3} }

func (m *CreateGroupRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *CreateGroupRequest) GetGroup() *Group {
	if m != nil {
		return m.Group
	}
	return nil
}

func (m *CreateGroupRequest) GetValidateOnly() bool {
	if m != nil {
		return m.ValidateOnly
	}
	return false
}

// The `UpdateGroup` request.
type UpdateGroupRequest struct {
	// The new definition of the group.  All fields of the existing group,
	// excepting `name`, are replaced with the corresponding fields of this group.
	Group *Group `protobuf:"bytes,2,opt,name=group" json:"group,omitempty"`
	// If true, validate this request but do not update the existing group.
	ValidateOnly bool `protobuf:"varint,3,opt,name=validate_only,json=validateOnly" json:"validate_only,omitempty"`
}

func (m *UpdateGroupRequest) Reset()                    { *m = UpdateGroupRequest{} }
func (m *UpdateGroupRequest) String() string            { return proto.CompactTextString(m) }
func (*UpdateGroupRequest) ProtoMessage()               {}
func (*UpdateGroupRequest) Descriptor() ([]byte, []int) { return fileDescriptor2, []int{4} }

func (m *UpdateGroupRequest) GetGroup() *Group {
	if m != nil {
		return m.Group
	}
	return nil
}

func (m *UpdateGroupRequest) GetValidateOnly() bool {
	if m != nil {
		return m.ValidateOnly
	}
	return false
}

// The `DeleteGroup` request. You can only delete a group if it has no children.
type DeleteGroupRequest struct {
	// The group to delete. The format is
	// `"projects/{project_id_or_number}/groups/{group_id}"`.
	Name string `protobuf:"bytes,3,opt,name=name" json:"name,omitempty"`
}

func (m *DeleteGroupRequest) Reset()                    { *m = DeleteGroupRequest{} }
func (m *DeleteGroupRequest) String() string            { return proto.CompactTextString(m) }
func (*DeleteGroupRequest) ProtoMessage()               {}
func (*DeleteGroupRequest) Descriptor() ([]byte, []int) { return fileDescriptor2, []int{5} }

func (m *DeleteGroupRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

// The `ListGroupMembers` request.
type ListGroupMembersRequest struct {
	// The group whose members are listed. The format is
	// `"projects/{project_id_or_number}/groups/{group_id}"`.
	Name string `protobuf:"bytes,7,opt,name=name" json:"name,omitempty"`
	// A positive number that is the maximum number of results to return.
	PageSize int32 `protobuf:"varint,3,opt,name=page_size,json=pageSize" json:"page_size,omitempty"`
	// If this field is not empty then it must contain the `nextPageToken` value
	// returned by a previous call to this method.  Using this field causes the
	// method to return additional results from the previous method call.
	PageToken string `protobuf:"bytes,4,opt,name=page_token,json=pageToken" json:"page_token,omitempty"`
	// An optional [list filter](/monitoring/api/learn_more#filtering) describing
	// the members to be returned.  The filter may reference the type, labels, and
	// metadata of monitored resources that comprise the group.
	// For example, to return only resources representing Compute Engine VM
	// instances, use this filter:
	//
	//     resource.type = "gce_instance"
	Filter string `protobuf:"bytes,5,opt,name=filter" json:"filter,omitempty"`
	// An optional time interval for which results should be returned. Only
	// members that were part of the group during the specified interval are
	// included in the response.  If no interval is provided then the group
	// membership over the last minute is returned.
	Interval *TimeInterval `protobuf:"bytes,6,opt,name=interval" json:"interval,omitempty"`
}

func (m *ListGroupMembersRequest) Reset()                    { *m = ListGroupMembersRequest{} }
func (m *ListGroupMembersRequest) String() string            { return proto.CompactTextString(m) }
func (*ListGroupMembersRequest) ProtoMessage()               {}
func (*ListGroupMembersRequest) Descriptor() ([]byte, []int) { return fileDescriptor2, []int{6} }

func (m *ListGroupMembersRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *ListGroupMembersRequest) GetPageSize() int32 {
	if m != nil {
		return m.PageSize
	}
	return 0
}

func (m *ListGroupMembersRequest) GetPageToken() string {
	if m != nil {
		return m.PageToken
	}
	return ""
}

func (m *ListGroupMembersRequest) GetFilter() string {
	if m != nil {
		return m.Filter
	}
	return ""
}

func (m *ListGroupMembersRequest) GetInterval() *TimeInterval {
	if m != nil {
		return m.Interval
	}
	return nil
}

// The `ListGroupMembers` response.
type ListGroupMembersResponse struct {
	// A set of monitored resources in the group.
	Members []*google_api4.MonitoredResource `protobuf:"bytes,1,rep,name=members" json:"members,omitempty"`
	// If there are more results than have been returned, then this field is
	// set to a non-empty value.  To see the additional results, use that value as
	// `pageToken` in the next call to this method.
	NextPageToken string `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken" json:"next_page_token,omitempty"`
	// The total number of elements matching this request.
	TotalSize int32 `protobuf:"varint,3,opt,name=total_size,json=totalSize" json:"total_size,omitempty"`
}

func (m *ListGroupMembersResponse) Reset()                    { *m = ListGroupMembersResponse{} }
func (m *ListGroupMembersResponse) String() string            { return proto.CompactTextString(m) }
func (*ListGroupMembersResponse) ProtoMessage()               {}
func (*ListGroupMembersResponse) Descriptor() ([]byte, []int) { return fileDescriptor2, []int{7} }

func (m *ListGroupMembersResponse) GetMembers() []*google_api4.MonitoredResource {
	if m != nil {
		return m.Members
	}
	return nil
}

func (m *ListGroupMembersResponse) GetNextPageToken() string {
	if m != nil {
		return m.NextPageToken
	}
	return ""
}

func (m *ListGroupMembersResponse) GetTotalSize() int32 {
	if m != nil {
		return m.TotalSize
	}
	return 0
}

func init() {
	proto.RegisterType((*ListGroupsRequest)(nil), "google.monitoring.v3.ListGroupsRequest")
	proto.RegisterType((*ListGroupsResponse)(nil), "google.monitoring.v3.ListGroupsResponse")
	proto.RegisterType((*GetGroupRequest)(nil), "google.monitoring.v3.GetGroupRequest")
	proto.RegisterType((*CreateGroupRequest)(nil), "google.monitoring.v3.CreateGroupRequest")
	proto.RegisterType((*UpdateGroupRequest)(nil), "google.monitoring.v3.UpdateGroupRequest")
	proto.RegisterType((*DeleteGroupRequest)(nil), "google.monitoring.v3.DeleteGroupRequest")
	proto.RegisterType((*ListGroupMembersRequest)(nil), "google.monitoring.v3.ListGroupMembersRequest")
	proto.RegisterType((*ListGroupMembersResponse)(nil), "google.monitoring.v3.ListGroupMembersResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for GroupService service

type GroupServiceClient interface {
	// Lists the existing groups.
	ListGroups(ctx context.Context, in *ListGroupsRequest, opts ...grpc.CallOption) (*ListGroupsResponse, error)
	// Gets a single group.
	GetGroup(ctx context.Context, in *GetGroupRequest, opts ...grpc.CallOption) (*Group, error)
	// Creates a new group.
	CreateGroup(ctx context.Context, in *CreateGroupRequest, opts ...grpc.CallOption) (*Group, error)
	// Updates an existing group.
	// You can change any group attributes except `name`.
	UpdateGroup(ctx context.Context, in *UpdateGroupRequest, opts ...grpc.CallOption) (*Group, error)
	// Deletes an existing group.
	DeleteGroup(ctx context.Context, in *DeleteGroupRequest, opts ...grpc.CallOption) (*google_protobuf4.Empty, error)
	// Lists the monitored resources that are members of a group.
	ListGroupMembers(ctx context.Context, in *ListGroupMembersRequest, opts ...grpc.CallOption) (*ListGroupMembersResponse, error)
}

type groupServiceClient struct {
	cc *grpc.ClientConn
}

func NewGroupServiceClient(cc *grpc.ClientConn) GroupServiceClient {
	return &groupServiceClient{cc}
}

func (c *groupServiceClient) ListGroups(ctx context.Context, in *ListGroupsRequest, opts ...grpc.CallOption) (*ListGroupsResponse, error) {
	out := new(ListGroupsResponse)
	err := grpc.Invoke(ctx, "/google.monitoring.v3.GroupService/ListGroups", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *groupServiceClient) GetGroup(ctx context.Context, in *GetGroupRequest, opts ...grpc.CallOption) (*Group, error) {
	out := new(Group)
	err := grpc.Invoke(ctx, "/google.monitoring.v3.GroupService/GetGroup", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *groupServiceClient) CreateGroup(ctx context.Context, in *CreateGroupRequest, opts ...grpc.CallOption) (*Group, error) {
	out := new(Group)
	err := grpc.Invoke(ctx, "/google.monitoring.v3.GroupService/CreateGroup", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *groupServiceClient) UpdateGroup(ctx context.Context, in *UpdateGroupRequest, opts ...grpc.CallOption) (*Group, error) {
	out := new(Group)
	err := grpc.Invoke(ctx, "/google.monitoring.v3.GroupService/UpdateGroup", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *groupServiceClient) DeleteGroup(ctx context.Context, in *DeleteGroupRequest, opts ...grpc.CallOption) (*google_protobuf4.Empty, error) {
	out := new(google_protobuf4.Empty)
	err := grpc.Invoke(ctx, "/google.monitoring.v3.GroupService/DeleteGroup", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *groupServiceClient) ListGroupMembers(ctx context.Context, in *ListGroupMembersRequest, opts ...grpc.CallOption) (*ListGroupMembersResponse, error) {
	out := new(ListGroupMembersResponse)
	err := grpc.Invoke(ctx, "/google.monitoring.v3.GroupService/ListGroupMembers", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for GroupService service

type GroupServiceServer interface {
	// Lists the existing groups.
	ListGroups(context.Context, *ListGroupsRequest) (*ListGroupsResponse, error)
	// Gets a single group.
	GetGroup(context.Context, *GetGroupRequest) (*Group, error)
	// Creates a new group.
	CreateGroup(context.Context, *CreateGroupRequest) (*Group, error)
	// Updates an existing group.
	// You can change any group attributes except `name`.
	UpdateGroup(context.Context, *UpdateGroupRequest) (*Group, error)
	// Deletes an existing group.
	DeleteGroup(context.Context, *DeleteGroupRequest) (*google_protobuf4.Empty, error)
	// Lists the monitored resources that are members of a group.
	ListGroupMembers(context.Context, *ListGroupMembersRequest) (*ListGroupMembersResponse, error)
}

func RegisterGroupServiceServer(s *grpc.Server, srv GroupServiceServer) {
	s.RegisterService(&_GroupService_serviceDesc, srv)
}

func _GroupService_ListGroups_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListGroupsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GroupServiceServer).ListGroups(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.monitoring.v3.GroupService/ListGroups",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GroupServiceServer).ListGroups(ctx, req.(*ListGroupsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GroupService_GetGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GroupServiceServer).GetGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.monitoring.v3.GroupService/GetGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GroupServiceServer).GetGroup(ctx, req.(*GetGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GroupService_CreateGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GroupServiceServer).CreateGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.monitoring.v3.GroupService/CreateGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GroupServiceServer).CreateGroup(ctx, req.(*CreateGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GroupService_UpdateGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GroupServiceServer).UpdateGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.monitoring.v3.GroupService/UpdateGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GroupServiceServer).UpdateGroup(ctx, req.(*UpdateGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GroupService_DeleteGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GroupServiceServer).DeleteGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.monitoring.v3.GroupService/DeleteGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GroupServiceServer).DeleteGroup(ctx, req.(*DeleteGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GroupService_ListGroupMembers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListGroupMembersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GroupServiceServer).ListGroupMembers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.monitoring.v3.GroupService/ListGroupMembers",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GroupServiceServer).ListGroupMembers(ctx, req.(*ListGroupMembersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _GroupService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.monitoring.v3.GroupService",
	HandlerType: (*GroupServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListGroups",
			Handler:    _GroupService_ListGroups_Handler,
		},
		{
			MethodName: "GetGroup",
			Handler:    _GroupService_GetGroup_Handler,
		},
		{
			MethodName: "CreateGroup",
			Handler:    _GroupService_CreateGroup_Handler,
		},
		{
			MethodName: "UpdateGroup",
			Handler:    _GroupService_UpdateGroup_Handler,
		},
		{
			MethodName: "DeleteGroup",
			Handler:    _GroupService_DeleteGroup_Handler,
		},
		{
			MethodName: "ListGroupMembers",
			Handler:    _GroupService_ListGroupMembers_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "google/monitoring/v3/group_service.proto",
}

func init() { proto.RegisterFile("google/monitoring/v3/group_service.proto", fileDescriptor2) }

var fileDescriptor2 = []byte{
	// 818 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x55, 0xcd, 0x6e, 0xdb, 0x46,
	0x10, 0x2e, 0x2d, 0x59, 0x96, 0x46, 0x36, 0x6c, 0x2f, 0x0c, 0x57, 0xa0, 0x7f, 0xa0, 0xd2, 0x3f,
	0x15, 0xdc, 0x9a, 0x44, 0xa5, 0x43, 0x81, 0x16, 0xf5, 0xc1, 0x6e, 0xe1, 0x16, 0xa8, 0x61, 0x83,
	0x76, 0x7b, 0xe8, 0x45, 0xa0, 0xa5, 0x11, 0xcb, 0x96, 0xdc, 0x65, 0xc9, 0x95, 0x5a, 0xbb, 0x30,
	0x90, 0x04, 0xc8, 0x21, 0x40, 0x6e, 0xb9, 0xe5, 0x96, 0x6b, 0x5e, 0x21, 0xa7, 0x3c, 0x43, 0x5e,
	0x21, 0xef, 0x91, 0x80, 0xcb, 0x5d, 0x89, 0xfa, 0xb5, 0x2f, 0xb9, 0x91, 0xbb, 0xdf, 0xec, 0xf7,
	0xcd, 0xec, 0x37, 0xb3, 0x50, 0x73, 0x19, 0x73, 0x7d, 0xb4, 0x02, 0x46, 0x3d, 0xce, 0x22, 0x8f,
	0xba, 0x56, 0xaf, 0x61, 0xb9, 0x11, 0xeb, 0x86, 0xcd, 0x18, 0xa3, 0x9e, 0xd7, 0x42, 0x33, 0x8c,
	0x18, 0x67, 0x64, 0x2d, 0x45, 0x9a, 0x03, 0xa4, 0xd9, 0x6b, 0xe8, 0x9b, 0x32, 0xde, 0x09, 0x3d,
	0xcb, 0xa1, 0x94, 0x71, 0x87, 0x7b, 0x8c, 0xc6, 0x69, 0x8c, 0xbe, 0x93, 0xd9, 0x95, 0x71, 0xd8,
	0x6e, 0x46, 0x18, 0xb3, 0x6e, 0xa4, 0x0e, 0xd6, 0xbf, 0x98, 0x28, 0xa1, 0xc5, 0x82, 0x80, 0x51,
	0x09, 0xa9, 0x4e, 0x57, 0x29, 0x11, 0x1b, 0x12, 0x21, 0xfe, 0xae, 0xbb, 0x1d, 0x0b, 0x83, 0x90,
	0xdf, 0xa4, 0x9b, 0xc6, 0x07, 0x0d, 0x56, 0x7f, 0xf5, 0x62, 0x7e, 0x9a, 0x04, 0xc4, 0x36, 0xfe,
	0xd3, 0xc5, 0x98, 0x13, 0x02, 0x79, 0xea, 0x04, 0x58, 0x59, 0xa8, 0x6a, 0xb5, 0x92, 0x2d, 0xbe,
	0xc9, 0xd7, 0xb0, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0x11, 0xd2, 0x26, 0xeb, 0x34, 0x05, 0x43, 0x65,
	0x2e, 0x01, 0xfc, 0xfc, 0x99, 0xbd, 0xac, 0xb6, 0xce, 0x3b, 0xe2, 0x24, 0x62, 0x02, 0x71, 0x68,
	0x0b, 0x63, 0xce, 0xa2, 0x78, 0x00, 0xcf, 0x49, 0xf8, 0x4a, 0x7f, 0x4f, 0xe1, 0xeb, 0xb0, 0xd6,
	0xc6, 0xb8, 0x85, 0xb4, 0xed, 0x50, 0x9e, 0x89, 0xc8, 0xcb, 0x08, 0x92, 0xd9, 0x55, 0x31, 0x1b,
	0x50, 0x0a, 0x1d, 0x17, 0x9b, 0xb1, 0x77, 0x8b, 0x95, 0xf9, 0xaa, 0x56, 0x9b, 0xb7, 0x8b, 0xc9,
	0xc2, 0xa5, 0x77, 0x8b, 0x64, 0x0b, 0x40, 0x6c, 0x72, 0xf6, 0x37, 0xd2, 0x4a, 0x41, 0x24, 0x22,
	0xe0, 0x57, 0xc9, 0xc2, 0x71, 0x11, 0x0a, 0x1d, 0xcf, 0xe7, 0x18, 0x19, 0x0c, 0x48, 0xb6, 0x00,
	0x71, 0xc8, 0x68, 0x8c, 0xe4, 0x1b, 0x98, 0x4f, 0x05, 0x68, 0xd5, 0x5c, 0xad, 0x5c, 0xdf, 0x30,
	0x27, 0x5d, 0xb1, 0x29, 0x82, 0xec, 0x14, 0x49, 0xf6, 0x61, 0x99, 0xe2, 0x7f, 0xbc, 0x99, 0xa1,
	0x15, 0xe5, 0xb1, 0x97, 0x92, 0xe5, 0x0b, 0x45, 0x6d, 0xec, 0xc1, 0xf2, 0x29, 0xa6, 0x7c, 0xa3,
	0xf5, 0xce, 0x0d, 0xea, 0x6d, 0x3c, 0xd2, 0x80, 0x9c, 0x44, 0xe8, 0x70, 0x9c, 0x08, 0xcd, 0x67,
	0xae, 0xa6, 0x2f, 0x36, 0xe1, 0x7b, 0x98, 0xd8, 0x1d, 0x58, 0xea, 0x39, 0xbe, 0xd7, 0x76, 0x38,
	0x36, 0x19, 0xf5, 0x6f, 0x04, 0x75, 0xd1, 0x5e, 0x54, 0x8b, 0xe7, 0xd4, 0xbf, 0x31, 0x7c, 0x20,
	0xbf, 0x85, 0xed, 0x51, 0x05, 0x9f, 0x8a, 0xad, 0x06, 0xe4, 0x47, 0xf4, 0x71, 0x4a, 0xbe, 0xd9,
	0xd2, 0xbc, 0xd5, 0xe0, 0xf3, 0xfe, 0x9d, 0x9d, 0x61, 0x70, 0x8d, 0xd1, 0x4c, 0xeb, 0x0e, 0x19,
	0x25, 0x37, 0xd3, 0x28, 0xf9, 0x11, 0xa3, 0x90, 0x75, 0x65, 0x14, 0xe1, 0xb0, 0x92, 0x2d, 0xff,
	0xc8, 0x11, 0x14, 0x3d, 0xca, 0x31, 0xea, 0x39, 0xbe, 0x70, 0x57, 0xb9, 0x6e, 0x4c, 0x2e, 0xc4,
	0x95, 0x17, 0xe0, 0x2f, 0x12, 0x69, 0xf7, 0x63, 0x8c, 0x97, 0x1a, 0x54, 0xc6, 0x73, 0x90, 0xee,
	0xfb, 0x16, 0x16, 0x82, 0x74, 0x49, 0xfa, 0x6f, 0x4b, 0x9d, 0xed, 0x84, 0x9e, 0x79, 0xa6, 0xc6,
	0x85, 0x2d, 0xa7, 0x85, 0xad, 0xd0, 0x0f, 0xf5, 0x60, 0x92, 0x34, 0x67, 0xdc, 0xf1, 0xb3, 0x25,
	0x29, 0x89, 0x95, 0xa4, 0x26, 0xf5, 0x37, 0x05, 0x58, 0x14, 0xc2, 0x2e, 0xd3, 0x39, 0x47, 0x9e,
	0x6a, 0x00, 0x83, 0x2e, 0x21, 0x5f, 0x4e, 0x4e, 0x75, 0x6c, 0x90, 0xe8, 0xb5, 0xfb, 0x81, 0x69,
	0xca, 0xc6, 0xee, 0x93, 0x77, 0xef, 0x5f, 0xcc, 0x6d, 0x93, 0xcd, 0x64, 0x7c, 0xfd, 0x9f, 0x5c,
	0xdb, 0x0f, 0x61, 0xc4, 0xfe, 0xc2, 0x16, 0x8f, 0xad, 0x83, 0xbb, 0x74, 0xa0, 0xc5, 0xa4, 0x07,
	0x45, 0xd5, 0x3b, 0x64, 0x6f, 0x8a, 0xf1, 0x86, 0x7b, 0x4b, 0x9f, 0xe5, 0x4f, 0x63, 0x5f, 0xb0,
	0x56, 0xc9, 0xf6, 0x24, 0x56, 0x49, 0x6a, 0x1d, 0xdc, 0x91, 0xc7, 0x1a, 0x94, 0x33, 0xcd, 0x48,
	0xa6, 0xe4, 0x35, 0xde, 0xaf, 0xb3, 0xe9, 0xbf, 0x12, 0xf4, 0x7b, 0xc6, 0xcc, 0xa4, 0xbf, 0x93,
	0x4d, 0xf4, 0x4c, 0x83, 0x72, 0xa6, 0x1d, 0xa7, 0x69, 0x18, 0xef, 0xd8, 0xd9, 0x1a, 0x1a, 0x42,
	0xc3, 0xa1, 0xbe, 0x2b, 0x34, 0xa4, 0x0f, 0xc7, 0xd4, 0x42, 0x28, 0x2d, 0xff, 0x42, 0x39, 0xd3,
	0xab, 0xd3, 0xa4, 0x8c, 0xb7, 0xb3, 0xbe, 0xae, 0x90, 0xea, 0x35, 0x32, 0x7f, 0x4a, 0x5e, 0x23,
	0x75, 0x11, 0x07, 0xf7, 0x5d, 0xc4, 0x2b, 0x0d, 0x56, 0x46, 0xdb, 0x86, 0x1c, 0xde, 0xe3, 0xb2,
	0xe1, 0x11, 0xa1, 0x9b, 0x0f, 0x85, 0x4b, 0x6b, 0x9a, 0x42, 0x5b, 0x8d, 0xec, 0xcf, 0xd6, 0x66,
	0xc9, 0x26, 0x3c, 0x7e, 0xae, 0x41, 0xa5, 0xc5, 0x82, 0x89, 0x2c, 0xc7, 0xab, 0xd9, 0xbe, 0xba,
	0x48, 0x8a, 0x70, 0xa1, 0xfd, 0x71, 0x24, 0xa1, 0x2e, 0xf3, 0x1d, 0xea, 0x9a, 0x2c, 0x72, 0x2d,
	0x17, 0xa9, 0x28, 0x91, 0x95, 0x6e, 0x39, 0xa1, 0x17, 0x0f, 0xbf, 0xf1, 0xdf, 0x0f, 0xfe, 0x5e,
	0xcf, 0xe9, 0xa7, 0xe9, 0x01, 0x27, 0x3e, 0xeb, 0xb6, 0xd5, 0x80, 0x48, 0x18, 0x7f, 0x6f, 0x5c,
	0x17, 0xc4, 0x39, 0x8d, 0x8f, 0x01, 0x00, 0x00, 0xff, 0xff, 0x1b, 0xec, 0x77, 0x3f, 0xd0, 0x08,
	0x00, 0x00,
}

package transcoder

import (
	"fmt"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// HTTPRule represents the HTTP binding for a gRPC method.
type HTTPRule struct {
	Method       string // GET, POST, PUT, DELETE, PATCH
	Pattern      string // URL pattern like "/v1/messages/{id}"
	Body         string // Request body field name, "*" for whole message, "" for no body
	ResponseBody string // Response body field name, "" for whole message
}

// MethodInfo contains information about a gRPC method.
type MethodInfo struct {
	ServiceName       string
	MethodName        string
	FullName          string
	InputType         protoreflect.MessageDescriptor
	OutputType        protoreflect.MessageDescriptor
	HTTPRules         []HTTPRule
	IsClientStreaming bool
	IsServerStreaming bool
}

// ServiceInfo contains information about a gRPC service.
type ServiceInfo struct {
	Name     string
	FullName string
	Methods  map[string]*MethodInfo // method name -> info
}

// ParsedDescriptor contains parsed proto descriptor information.
type ParsedDescriptor struct {
	Services map[string]*ServiceInfo // service name -> info
	Files    *protoregistry.Files
	Types    *protoregistry.Types
}

// DescriptorParser parses proto FileDescriptorSet and extracts service information.
type DescriptorParser struct {
	log *log.Helper
}

// NewDescriptorParser creates a new DescriptorParser.
func NewDescriptorParser(logger *log.Helper) *DescriptorParser {
	return &DescriptorParser{
		log: logger,
	}
}

// Parse parses a serialized FileDescriptorSet and extracts service information.
func (p *DescriptorParser) Parse(protoDescriptor []byte) (*ParsedDescriptor, error) {
	if len(protoDescriptor) == 0 {
		return nil, fmt.Errorf("empty proto descriptor")
	}

	fds := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(protoDescriptor, fds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal FileDescriptorSet: %w", err)
	}

	files, err := protodesc.NewFiles(fds)
	if err != nil {
		return nil, fmt.Errorf("failed to create file registry: %w", err)
	}

	types := &protoregistry.Types{}

	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		p.registerTypes(types, fd)
		return true
	})

	parsed := &ParsedDescriptor{
		Services: make(map[string]*ServiceInfo),
		Files:    files,
		Types:    types,
	}

	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			sd := services.Get(i)
			serviceInfo := p.parseService(sd)
			parsed.Services[serviceInfo.Name] = serviceInfo
		}
		return true
	})

	p.log.Infof("Parsed %d services from proto descriptor", len(parsed.Services))

	return parsed, nil
}

// registerTypes registers all message and enum types from a file descriptor.
func (p *DescriptorParser) registerTypes(types *protoregistry.Types, fd protoreflect.FileDescriptor) {
	msgs := fd.Messages()
	for i := 0; i < msgs.Len(); i++ {
		p.registerMessage(types, msgs.Get(i))
	}

	enums := fd.Enums()
	for i := 0; i < enums.Len(); i++ {
		ed := enums.Get(i)
		if err := types.RegisterEnum(dynamicEnumType{ed}); err != nil {
			p.log.Warnf("Failed to register enum type %s: %v", ed.FullName(), err)
		}
	}
}

// dynamicEnumType wraps an EnumDescriptor to implement EnumType.
type dynamicEnumType struct {
	protoreflect.EnumDescriptor
}

func (d dynamicEnumType) New(n protoreflect.EnumNumber) protoreflect.Enum {
	return dynamicEnum{d.EnumDescriptor, n}
}

func (d dynamicEnumType) Descriptor() protoreflect.EnumDescriptor {
	return d.EnumDescriptor
}

type dynamicEnum struct {
	desc protoreflect.EnumDescriptor
	num  protoreflect.EnumNumber
}

func (d dynamicEnum) Descriptor() protoreflect.EnumDescriptor { return d.desc }
func (d dynamicEnum) Type() protoreflect.EnumType             { return dynamicEnumType{d.desc} }
func (d dynamicEnum) Number() protoreflect.EnumNumber         { return d.num }

// dynamicMessageType wraps a MessageDescriptor to implement MessageType.
type dynamicMessageType struct {
	protoreflect.MessageDescriptor
}

func (d dynamicMessageType) New() protoreflect.Message {
	return dynamicpb.NewMessage(d.MessageDescriptor)
}

func (d dynamicMessageType) Zero() protoreflect.Message {
	return dynamicpb.NewMessage(d.MessageDescriptor)
}

func (d dynamicMessageType) Descriptor() protoreflect.MessageDescriptor {
	return d.MessageDescriptor
}

// registerMessage recursively registers a message and its nested types.
func (p *DescriptorParser) registerMessage(types *protoregistry.Types, md protoreflect.MessageDescriptor) {
	if err := types.RegisterMessage(dynamicMessageType{md}); err != nil {
		p.log.Warnf("Failed to register message type %s: %v", md.FullName(), err)
	}

	nested := md.Messages()
	for i := 0; i < nested.Len(); i++ {
		p.registerMessage(types, nested.Get(i))
	}

	enums := md.Enums()
	for i := 0; i < enums.Len(); i++ {
		if err := types.RegisterEnum(dynamicEnumType{enums.Get(i)}); err != nil {
			p.log.Warnf("Failed to register nested enum type %s: %v", enums.Get(i).FullName(), err)
		}
	}
}

// parseService extracts service information from a service descriptor.
func (p *DescriptorParser) parseService(sd protoreflect.ServiceDescriptor) *ServiceInfo {
	info := &ServiceInfo{
		Name:     string(sd.Name()),
		FullName: string(sd.FullName()),
		Methods:  make(map[string]*MethodInfo),
	}

	methods := sd.Methods()
	for i := 0; i < methods.Len(); i++ {
		md := methods.Get(i)
		methodInfo := p.parseMethod(sd, md)
		info.Methods[methodInfo.MethodName] = methodInfo
	}

	return info
}

// parseMethod extracts method information including HTTP bindings.
func (p *DescriptorParser) parseMethod(sd protoreflect.ServiceDescriptor, md protoreflect.MethodDescriptor) *MethodInfo {
	info := &MethodInfo{
		ServiceName:       string(sd.Name()),
		MethodName:        string(md.Name()),
		FullName:          string(md.FullName()),
		InputType:         md.Input(),
		OutputType:        md.Output(),
		IsClientStreaming: md.IsStreamingClient(),
		IsServerStreaming: md.IsStreamingServer(),
		HTTPRules:         make([]HTTPRule, 0),
	}

	opts := md.Options()
	if opts != nil {
		extracted := p.extractHTTPRule(opts)
		if extracted != nil {
			info.HTTPRules = append(info.HTTPRules, extracted.Primary)
			info.HTTPRules = append(info.HTTPRules, extracted.Additional...)
		}
	}

	return info
}

// ExtractedHTTPRules contains the primary HTTP rule and any additional bindings.
type ExtractedHTTPRules struct {
	Primary    HTTPRule
	Additional []HTTPRule
}

// extractHTTPRule extracts the google.api.http annotation from method options.
func (p *DescriptorParser) extractHTTPRule(opts protoreflect.ProtoMessage) *ExtractedHTTPRules {
	ext := proto.GetExtension(opts, annotations.E_Http)
	if ext == nil {
		return nil
	}

	rule, ok := ext.(*annotations.HttpRule)
	if !ok || rule == nil {
		return nil
	}

	result := &ExtractedHTTPRules{
		Primary:    p.convertHTTPRule(rule),
		Additional: make([]HTTPRule, 0),
	}

	for _, additionalRule := range rule.GetAdditionalBindings() {
		result.Additional = append(result.Additional, p.convertHTTPRule(additionalRule))
	}

	return result
}

// convertHTTPRule converts a google.api.HttpRule to our HTTPRule struct.
func (p *DescriptorParser) convertHTTPRule(rule *annotations.HttpRule) HTTPRule {
	hr := HTTPRule{
		Body:         rule.GetBody(),
		ResponseBody: rule.GetResponseBody(),
	}

	switch pattern := rule.GetPattern().(type) {
	case *annotations.HttpRule_Get:
		hr.Method = "GET"
		hr.Pattern = pattern.Get
	case *annotations.HttpRule_Post:
		hr.Method = "POST"
		hr.Pattern = pattern.Post
	case *annotations.HttpRule_Put:
		hr.Method = "PUT"
		hr.Pattern = pattern.Put
	case *annotations.HttpRule_Delete:
		hr.Method = "DELETE"
		hr.Pattern = pattern.Delete
	case *annotations.HttpRule_Patch:
		hr.Method = "PATCH"
		hr.Pattern = pattern.Patch
	case *annotations.HttpRule_Custom:
		hr.Method = pattern.Custom.GetKind()
		hr.Pattern = pattern.Custom.GetPath()
	}

	return hr
}

// GetMethod looks up a method by service and method name.
func (pd *ParsedDescriptor) GetMethod(serviceName, methodName string) (*MethodInfo, bool) {
	service, ok := pd.Services[serviceName]
	if !ok {
		return nil, false
	}
	method, ok := service.Methods[methodName]
	return method, ok
}

// routeMatch represents a matched route with its specificity score.
type routeMatch struct {
	method      *MethodInfo
	params      map[string]string
	specificity int
}

// FindMethodByHTTP finds a method that matches the given HTTP method and path.
// It prioritizes more specific routes (fewer path parameters) over parameterized ones.
func (pd *ParsedDescriptor) FindMethodByHTTP(httpMethod, path string) (*MethodInfo, map[string]string, bool) {
	var matches []routeMatch

	for _, service := range pd.Services {
		for _, method := range service.Methods {
			for _, rule := range method.HTTPRules {
				if strings.EqualFold(rule.Method, httpMethod) {
					params, matched := MatchPath(rule.Pattern, path)
					if matched {
						specificity := calculateSpecificity(rule.Pattern)
						matches = append(matches, routeMatch{
							method:      method,
							params:      params,
							specificity: specificity,
						})
					}
				}
			}
		}
	}

	if len(matches) == 0 {
		return nil, nil, false
	}

	best := matches[0]
	for _, m := range matches[1:] {
		if m.specificity > best.specificity {
			best = m
		}
	}

	return best.method, best.params, true
}

// calculateSpecificity calculates how specific a route pattern is.
// Higher values mean more specific (more literal segments, fewer parameters).
func calculateSpecificity(pattern string) int {
	parts := strings.Split(strings.Trim(pattern, "/"), "/")
	specificity := 0
	for _, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			if strings.Contains(part, "**") {
				specificity -= 10
			}
		} else {
			specificity += 10
		}
	}
	specificity += len(parts)
	return specificity
}

// MatchPath checks if a path matches a pattern and extracts path parameters.
// Pattern: /v1/messages/{id} matches path: /v1/messages/123 returns {id: 123}
func MatchPath(pattern, path string) (map[string]string, bool) {
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(path, "/"), "/")

	if len(patternParts) != len(pathParts) {
		if !strings.Contains(pattern, "**") {
			return nil, false
		}
	}

	params := make(map[string]string)

	for i, patternPart := range patternParts {
		if i >= len(pathParts) {
			return nil, false
		}

		if strings.HasPrefix(patternPart, "{") && strings.HasSuffix(patternPart, "}") {
			paramName := strings.TrimSuffix(strings.TrimPrefix(patternPart, "{"), "}")

			if idx := strings.Index(paramName, "="); idx > 0 {
				paramName = paramName[:idx]
			}

			if paramName == "**" || strings.HasSuffix(paramName, "=**") {
				params[strings.TrimSuffix(paramName, "=**")] = strings.Join(pathParts[i:], "/")
				return params, true
			}

			params[paramName] = pathParts[i]
		} else if patternPart != pathParts[i] {
			return nil, false
		}
	}

	return params, true
}

// ListMethods returns all methods in the parsed descriptor.
func (pd *ParsedDescriptor) ListMethods() []*MethodInfo {
	var methods []*MethodInfo
	for _, service := range pd.Services {
		for _, method := range service.Methods {
			methods = append(methods, method)
		}
	}
	return methods
}

// ListServices returns all service names.
func (pd *ParsedDescriptor) ListServices() []string {
	var services []string
	for name := range pd.Services {
		services = append(services, name)
	}
	return services
}

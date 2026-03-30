package transcoder

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// RequestBuilder builds protobuf request messages from HTTP requests.
type RequestBuilder struct {
	log *log.Helper
}

// NewRequestBuilder creates a new RequestBuilder.
func NewRequestBuilder(logger *log.Helper) *RequestBuilder {
	return &RequestBuilder{
		log: logger,
	}
}

// BuildRequest builds a protobuf message from an HTTP request.
func (b *RequestBuilder) BuildRequest(
	req *http.Request,
	method *MethodInfo,
	httpRule HTTPRule,
	pathParams map[string]string,
) (*dynamicpb.Message, error) {
	msg := dynamicpb.NewMessage(method.InputType)

	queryParams := req.URL.Query()

	var bodyData map[string]interface{}
	if req.Body != nil && req.ContentLength > 0 {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}

		if len(bodyBytes) > 0 {
			if httpRule.Body == "*" {
				if err := protojson.Unmarshal(bodyBytes, msg); err != nil {
					return nil, fmt.Errorf("failed to unmarshal body to proto: %w", err)
				}
			} else if httpRule.Body != "" {
				if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
					return nil, fmt.Errorf("failed to parse body JSON: %w", err)
				}
				if err := b.setField(msg, httpRule.Body, bodyData); err != nil {
					return nil, fmt.Errorf("failed to set body field %s: %w", httpRule.Body, err)
				}
			}
		}
	}

	for name, value := range pathParams {
		if err := b.setFieldByPath(msg, name, value); err != nil {
			b.log.Warnf("Failed to set path param %s=%s: %v", name, value, err)
		}
	}

	for name, values := range queryParams {
		if _, exists := pathParams[name]; exists {
			continue
		}
		if len(values) > 0 {
			if err := b.setFieldByPath(msg, name, values[0]); err != nil {
				b.log.Warnf("Failed to set query param %s=%s: %v", name, values[0], err)
			}
		}
	}

	return msg, nil
}

// setField sets a field on a message from a JSON value.
func (b *RequestBuilder) setField(msg *dynamicpb.Message, fieldName string, value interface{}) error {
	fd := msg.Descriptor().Fields().ByJSONName(fieldName)
	if fd == nil {
		fd = msg.Descriptor().Fields().ByName(protoreflect.Name(fieldName))
	}
	if fd == nil {
		fd = b.findField(msg.Descriptor(), fieldName)
	}
	if fd == nil {
		return fmt.Errorf("field not found: %s", fieldName)
	}

	if fd.Kind() == protoreflect.MessageKind {
		jsonBytes, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
		subMsg := dynamicpb.NewMessage(fd.Message())
		if err := protojson.Unmarshal(jsonBytes, subMsg); err != nil {
			return fmt.Errorf("failed to unmarshal to message field: %w", err)
		}
		msg.Set(fd, protoreflect.ValueOf(subMsg))
	} else {
		pv, err := b.convertToProtoValue(fd, value)
		if err != nil {
			return err
		}
		msg.Set(fd, pv)
	}

	return nil
}

// setFieldByPath sets a field by its path (supports nested paths like "user.name").
func (b *RequestBuilder) setFieldByPath(msg *dynamicpb.Message, path string, value string) error {
	parts := strings.Split(path, ".")
	current := msg

	for i, part := range parts {
		fd := b.findField(current.Descriptor(), part)
		if fd == nil {
			return fmt.Errorf("field not found: %s in path %s", part, path)
		}

		if i == len(parts)-1 {
			pv, err := b.parseStringValue(fd, value)
			if err != nil {
				return err
			}
			current.Set(fd, pv)
		} else {
			if fd.Kind() != protoreflect.MessageKind {
				return fmt.Errorf("cannot navigate into non-message field: %s", part)
			}

			var nested *dynamicpb.Message
			if current.Has(fd) {
				nested = current.Get(fd).Message().Interface().(*dynamicpb.Message)
			} else {
				nested = dynamicpb.NewMessage(fd.Message())
				current.Set(fd, protoreflect.ValueOf(nested))
			}
			current = nested
		}
	}

	return nil
}

// findField finds a field descriptor by various name formats.
func (b *RequestBuilder) findField(md protoreflect.MessageDescriptor, name string) protoreflect.FieldDescriptor {
	fields := md.Fields()

	if fd := fields.ByJSONName(name); fd != nil {
		return fd
	}

	if fd := fields.ByName(protoreflect.Name(name)); fd != nil {
		return fd
	}

	snakeName := toSnakeCase(name)
	if fd := fields.ByName(protoreflect.Name(snakeName)); fd != nil {
		return fd
	}

	camelName := toCamelCase(name)
	if fd := fields.ByJSONName(camelName); fd != nil {
		return fd
	}

	return nil
}

// parseStringValue converts a string value to a protoreflect.Value.
func (b *RequestBuilder) parseStringValue(fd protoreflect.FieldDescriptor, value string) (protoreflect.Value, error) {
	if fd.IsList() {
		list := dynamicpb.NewMessage(fd.ContainingMessage()).NewField(fd).List()
		values := strings.Split(value, ",")
		for _, v := range values {
			elem, err := b.parseSingleValue(fd, strings.TrimSpace(v))
			if err != nil {
				return protoreflect.Value{}, err
			}
			list.Append(elem)
		}
		return protoreflect.ValueOfList(list), nil
	}

	return b.parseSingleValue(fd, value)
}

// parseSingleValue parses a single string value based on field kind.
func (b *RequestBuilder) parseSingleValue(fd protoreflect.FieldDescriptor, value string) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		bv, err := strconv.ParseBool(value)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("invalid bool value: %s", value)
		}
		return protoreflect.ValueOfBool(bv), nil

	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		iv, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("invalid int32 value: %s", value)
		}
		return protoreflect.ValueOfInt32(int32(iv)), nil

	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		iv, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("invalid int64 value: %s", value)
		}
		return protoreflect.ValueOfInt64(iv), nil

	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		uv, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("invalid uint32 value: %s", value)
		}
		return protoreflect.ValueOfUint32(uint32(uv)), nil

	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		uv, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("invalid uint64 value: %s", value)
		}
		return protoreflect.ValueOfUint64(uv), nil

	case protoreflect.FloatKind:
		fv, err := strconv.ParseFloat(value, 32)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("invalid float value: %s", value)
		}
		return protoreflect.ValueOfFloat32(float32(fv)), nil

	case protoreflect.DoubleKind:
		fv, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("invalid double value: %s", value)
		}
		return protoreflect.ValueOfFloat64(fv), nil

	case protoreflect.StringKind:
		return protoreflect.ValueOfString(value), nil

	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte(value)), nil

	case protoreflect.EnumKind:
		if iv, err := strconv.ParseInt(value, 10, 32); err == nil {
			return protoreflect.ValueOfEnum(protoreflect.EnumNumber(iv)), nil
		}
		enumValues := fd.Enum().Values()
		for i := 0; i < enumValues.Len(); i++ {
			ev := enumValues.Get(i)
			if string(ev.Name()) == value || strings.EqualFold(string(ev.Name()), value) {
				return protoreflect.ValueOfEnum(ev.Number()), nil
			}
		}
		return protoreflect.Value{}, fmt.Errorf("unknown enum value: %s", value)

	case protoreflect.MessageKind:
		fullName := fd.Message().FullName()
		switch fullName {
		case "google.protobuf.StringValue":
			wrapper := dynamicpb.NewMessage(fd.Message())
			wrapper.Set(fd.Message().Fields().ByName("value"), protoreflect.ValueOfString(value))
			return protoreflect.ValueOfMessage(wrapper), nil
		case "google.protobuf.Int32Value", "google.protobuf.Int64Value":
			wrapper := dynamicpb.NewMessage(fd.Message())
			iv, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return protoreflect.Value{}, err
			}
			if fullName == "google.protobuf.Int32Value" {
				wrapper.Set(fd.Message().Fields().ByName("value"), protoreflect.ValueOfInt32(int32(iv)))
			} else {
				wrapper.Set(fd.Message().Fields().ByName("value"), protoreflect.ValueOfInt64(iv))
			}
			return protoreflect.ValueOfMessage(wrapper), nil
		case "google.protobuf.BoolValue":
			wrapper := dynamicpb.NewMessage(fd.Message())
			bv, err := strconv.ParseBool(value)
			if err != nil {
				return protoreflect.Value{}, err
			}
			wrapper.Set(fd.Message().Fields().ByName("value"), protoreflect.ValueOfBool(bv))
			return protoreflect.ValueOfMessage(wrapper), nil
		}
		return protoreflect.Value{}, fmt.Errorf("cannot parse string to message type: %s", fullName)

	default:
		return protoreflect.Value{}, fmt.Errorf("unsupported field kind: %v", fd.Kind())
	}
}

// convertToProtoValue converts a Go interface{} to a protoreflect.Value.
func (b *RequestBuilder) convertToProtoValue(fd protoreflect.FieldDescriptor, value interface{}) (protoreflect.Value, error) {
	switch v := value.(type) {
	case string:
		return b.parseSingleValue(fd, v)
	case float64: // JSON numbers are float64
		switch fd.Kind() {
		case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
			return protoreflect.ValueOfInt32(int32(v)), nil
		case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
			return protoreflect.ValueOfInt64(int64(v)), nil
		case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
			return protoreflect.ValueOfUint32(uint32(v)), nil
		case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
			return protoreflect.ValueOfUint64(uint64(v)), nil
		case protoreflect.FloatKind:
			return protoreflect.ValueOfFloat32(float32(v)), nil
		case protoreflect.DoubleKind:
			return protoreflect.ValueOfFloat64(v), nil
		case protoreflect.EnumKind:
			return protoreflect.ValueOfEnum(protoreflect.EnumNumber(v)), nil
		}
	case bool:
		return protoreflect.ValueOfBool(v), nil
	case nil:
		return protoreflect.Value{}, nil
	}
	return protoreflect.Value{}, fmt.Errorf("cannot convert %T to proto value", value)
}

func toSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && 'A' <= r && r <= 'Z' {
			result.WriteByte('_')
		}
		if 'A' <= r && r <= 'Z' {
			result.WriteByte(byte(r + 32))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func toCamelCase(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

// BuildQueryString builds a query string from message fields.
func (b *RequestBuilder) BuildQueryString(msg protoreflect.Message, exclude []string) url.Values {
	values := url.Values{}
	excludeMap := make(map[string]bool)
	for _, e := range exclude {
		excludeMap[e] = true
	}

	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		name := string(fd.JSONName())
		if excludeMap[name] || excludeMap[string(fd.Name())] {
			return true
		}

		switch fd.Kind() {
		case protoreflect.MessageKind:
			return true
		case protoreflect.BoolKind:
			values.Set(name, strconv.FormatBool(v.Bool()))
		case protoreflect.Int32Kind, protoreflect.Int64Kind, protoreflect.Sint32Kind, protoreflect.Sint64Kind:
			values.Set(name, strconv.FormatInt(v.Int(), 10))
		case protoreflect.Uint32Kind, protoreflect.Uint64Kind:
			values.Set(name, strconv.FormatUint(v.Uint(), 10))
		case protoreflect.FloatKind, protoreflect.DoubleKind:
			values.Set(name, strconv.FormatFloat(v.Float(), 'f', -1, 64))
		case protoreflect.StringKind:
			values.Set(name, v.String())
		case protoreflect.EnumKind:
			values.Set(name, strconv.FormatInt(int64(v.Enum()), 10))
		}

		return true
	})

	return values
}

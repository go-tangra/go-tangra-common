package transcoder

import (
	"encoding/json"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ResponseTransformer transforms gRPC responses to HTTP/JSON responses.
type ResponseTransformer struct {
	log            *log.Helper
	marshalOptions protojson.MarshalOptions
}

// NewResponseTransformer creates a new ResponseTransformer.
func NewResponseTransformer(logger *log.Helper) *ResponseTransformer {
	return &ResponseTransformer{
		log: logger,
		marshalOptions: protojson.MarshalOptions{
			UseProtoNames:   false,
			EmitUnpopulated: false,
			UseEnumNumbers:  false,
		},
	}
}

// TransformResponse converts a protobuf message to JSON bytes.
func (t *ResponseTransformer) TransformResponse(msg proto.Message, responseBody string) ([]byte, error) {
	if msg == nil {
		return []byte("{}"), nil
	}

	if responseBody != "" && responseBody != "*" {
		extracted, err := t.extractResponseBody(msg, responseBody)
		if err != nil {
			return nil, fmt.Errorf("failed to extract response body field %s: %w", responseBody, err)
		}
		msg = extracted
	}

	jsonBytes, err := t.marshalOptions.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	return jsonBytes, nil
}

// extractResponseBody extracts a specific field from the message as the response body.
func (t *ResponseTransformer) extractResponseBody(msg proto.Message, fieldName string) (proto.Message, error) {
	rm := msg.ProtoReflect()
	fd := rm.Descriptor().Fields().ByJSONName(fieldName)
	if fd == nil {
		fd = rm.Descriptor().Fields().ByName(protoreflect.Name(fieldName))
	}
	if fd == nil {
		return nil, fmt.Errorf("field not found: %s", fieldName)
	}

	if fd.Kind() != protoreflect.MessageKind {
		return nil, fmt.Errorf("response_body field must be a message type, got: %s", fd.Kind())
	}

	val := rm.Get(fd)
	if !val.IsValid() {
		return nil, nil
	}

	return val.Message().Interface(), nil
}

// TransformError converts a gRPC error to an HTTP error response.
func (t *ResponseTransformer) TransformError(err error) (int, []byte) {
	st, ok := status.FromError(err)
	if !ok {
		httpErr := HTTPError{
			Code:    500,
			Message: err.Error(),
		}
		jsonBytes, _ := json.Marshal(httpErr)
		return 500, jsonBytes
	}

	httpCode := t.grpcCodeToHTTP(st.Code())
	httpErr := HTTPError{
		Code:    httpCode,
		Message: st.Message(),
	}

	details := st.Details()
	if len(details) > 0 {
		httpErr.Details = details
	}

	jsonBytes, _ := json.Marshal(httpErr)
	return httpCode, jsonBytes
}

// grpcCodeToHTTP converts a gRPC status code to an HTTP status code.
func (t *ResponseTransformer) grpcCodeToHTTP(code codes.Code) int {
	switch code {
	case codes.OK:
		return 200
	case codes.Canceled:
		return 499
	case codes.Unknown:
		return 500
	case codes.InvalidArgument:
		return 400
	case codes.DeadlineExceeded:
		return 504
	case codes.NotFound:
		return 404
	case codes.AlreadyExists:
		return 409
	case codes.PermissionDenied:
		return 403
	case codes.ResourceExhausted:
		return 429
	case codes.FailedPrecondition:
		return 400
	case codes.Aborted:
		return 409
	case codes.OutOfRange:
		return 400
	case codes.Unimplemented:
		return 501
	case codes.Internal:
		return 500
	case codes.Unavailable:
		return 503
	case codes.DataLoss:
		return 500
	case codes.Unauthenticated:
		return 401
	default:
		return 500
	}
}

// TransformStreamingResponse transforms a streaming response.
func (t *ResponseTransformer) TransformStreamingResponse(msgs []proto.Message) ([]byte, error) {
	if len(msgs) == 0 {
		return []byte("[]"), nil
	}

	var results []json.RawMessage
	for _, msg := range msgs {
		jsonBytes, err := t.marshalOptions.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal streaming message: %w", err)
		}
		results = append(results, jsonBytes)
	}

	return json.Marshal(results)
}

// SetMarshalOptions allows customizing the protojson marshal options.
func (t *ResponseTransformer) SetMarshalOptions(opts protojson.MarshalOptions) {
	t.marshalOptions = opts
}

// GetMarshalOptions returns the current marshal options.
func (t *ResponseTransformer) GetMarshalOptions() protojson.MarshalOptions {
	return t.marshalOptions
}

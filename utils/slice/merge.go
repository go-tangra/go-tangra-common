package slice

import (
	"fmt"
	"strconv"
)

// MergeInPlace in-place merge (does not create a new slice, overwrites the original slice)
func MergeInPlace(slice1, slice2 []uint32) []uint32 {
	// Calculate the total required capacity
	totalLen := len(slice1) + len(slice2)

	// If slice1 doesn't have enough capacity, create a new slice that's large enough.
	if cap(slice1) < totalLen {
		newSlice := make([]uint32, len(slice1), totalLen)
		copy(newSlice, slice1)
		slice1 = newSlice
	}

	// Extend the length of slice1 and copy the elements of slice2
	slice1 = slice1[:totalLen]
	copy(slice1[len(slice1)-len(slice2):], slice2)

	return slice1
}

// MergeAndDeduplicateOrdered Ordered merge and deduplicate (no duplicate elements allowed, original order preserved)
func MergeAndDeduplicateOrdered(slice1, slice2 []uint32) []uint32 {
	seen := make(map[uint32]struct{})
	result := make([]uint32, 0, len(slice1)+len(slice2))

	// First add the elements of slice1 (maintain the order)
	for _, v := range slice1 {
		if _, exists := seen[v]; !exists {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}

	// Add the elements of slice2 (skipping the ones that already exist)
	for _, v := range slice2 {
		if _, exists := seen[v]; !exists {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}

	return result
}

// MergeAndDeduplicate Deduplicate and merge (no duplicate elements allowed, unordered)
func MergeAndDeduplicate(slice1, slice2 []uint32) []uint32 {
	set := make(map[uint32]struct{})
	for _, v := range slice1 {
		set[v] = struct{}{}
	}
	for _, v := range slice2 {
		set[v] = struct{}{}
	}

	result := make([]uint32, 0, len(set))
	for v := range set {
		result = append(result, v)
	}
	return result
}

// Unique removes duplicates from a slice while preserving the original order of elements. The generic type T needs to be comparable so that it can be used as a key in a map.
func Unique[T comparable](s []T) []T {
	if len(s) == 0 {
		return s
	}
	seen := make(map[T]struct{}, len(s))
	out := make([]T, 0, len(s))
	for _, v := range s {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

// Intersect calculates the intersection of two slices and returns a new slice containing the unique elements that appear in both slices. The generic type T needs to be comparable so that it can be used as a key in a map.
func Intersect[T comparable](a, b []T) []T {
	if len(a) == 0 || len(b) == 0 {
		return []T{}
	}
	m := make(map[T]struct{}, len(b))
	for _, v := range b {
		m[v] = struct{}{}
	}
	out := make([]T, 0, len(a))
	seen := make(map[T]struct{}, len(a))
	for _, v := range a {
		if _, ok := m[v]; ok {
			if _, s := seen[v]; !s {
				out = append(out, v)
				seen[v] = struct{}{}
			}
		}
	}
	return out
}

// NumberSliceToStrings converts a slice of numeric values into a slice of strings. It supports: int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64. For unknown types, it falls back to using fmt.Sprint.
func NumberSliceToStrings[T ~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~float32 | ~float64](s []T) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, 0, len(s))
	for _, v := range s {
		switch x := any(v).(type) {
		case int:
			out = append(out, strconv.FormatInt(int64(x), 10))
		case int8:
			out = append(out, strconv.FormatInt(int64(x), 10))
		case int16:
			out = append(out, strconv.FormatInt(int64(x), 10))
		case int32:
			out = append(out, strconv.FormatInt(int64(x), 10))
		case int64:
			out = append(out, strconv.FormatInt(x, 10))
		case uint:
			out = append(out, strconv.FormatUint(uint64(x), 10))
		case uint8:
			out = append(out, strconv.FormatUint(uint64(x), 10))
		case uint16:
			out = append(out, strconv.FormatUint(uint64(x), 10))
		case uint32:
			out = append(out, strconv.FormatUint(uint64(x), 10))
		case uint64:
			out = append(out, strconv.FormatUint(x, 10))
		case float32:
			out = append(out, strconv.FormatFloat(float64(x), 'f', -1, 32))
		case float64:
			out = append(out, strconv.FormatFloat(x, 'f', -1, 64))
		default:
			out = append(out, fmt.Sprint(v))
		}
	}
	return out
}

package api

import (
	"reflect"
	"testing"
)

func TestDrainIMSIChannel(t *testing.T) {
	imsiChan := make(chan string, 3)
	imsiChan <- "460020000000011"
	imsiChan <- "460020000000101"
	imsiChan <- "460020000000102"
	close(imsiChan)

	var got []string
	drainIMSIChannel(imsiChan, func(imsi string) {
		got = append(got, imsi)
	})

	want := []string{"460020000000011", "460020000000101", "460020000000102"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("drained IMSIs = %v, want %v", got, want)
	}
}

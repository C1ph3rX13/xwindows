package xsyscall

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestNtQueueApcThreadEx(t *testing.T) {
	type args struct {
		threadHandle  windows.Handle
		userApcOption uintptr
		apcRoutine    uintptr
	}
	var tests []struct {
		name    string
		args    args
		wantErr bool
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := NtQueueApcThreadEx(tt.args.threadHandle, tt.args.userApcOption, tt.args.apcRoutine); (err != nil) != tt.wantErr {
				t.Errorf("NtQueueApcThreadEx() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

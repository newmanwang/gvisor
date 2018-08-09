// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"os"
	"runtime/debug"
	"strings"
	"syscall"
	"fmt"
	"io"
	"strconv"

	"context"
	"flag"
	"github.com/google/subcommands"
	"github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
	"golang.org/x/sys/unix"
)

// Boot implements subcommands.Command for the "boot" command which starts a
// new sandbox. It should not be called directly.
type Boot struct {
	// bundleDir is the path to the bundle directory.
	bundleDir string

	// controllerFD is the file descriptor of a stream socket for the
	// control server that is donated to this process.
	controllerFD int

	// ioFDs is the list of FDs used to connect to FS gofers.
	ioFDs intFlags

	// console is set to true if the sandbox should allow terminal ioctl(2)
	// syscalls.
	console bool

	// applyCaps determines if capabilities defined in the spec should be applied
	// to the process.
	applyCaps bool
}

// Name implements subcommands.Command.Name.
func (*Boot) Name() string {
	return "boot"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Boot) Synopsis() string {
	return "launch a sandbox process (internal use only)"
}

// Usage implements subcommands.Command.Usage.
func (*Boot) Usage() string {
	return `boot [flags]`
}

// SetFlags implements subcommands.Command.SetFlags.
func (b *Boot) SetFlags(f *flag.FlagSet) {
	f.StringVar(&b.bundleDir, "bundle", "", "required path to the root of the bundle directory")
	f.IntVar(&b.controllerFD, "controller-fd", -1, "required FD of a stream socket for the control server that must be donated to this process")
	f.Var(&b.ioFDs, "io-fds", "list of FDs to connect 9P clients. They must follow this order: root first, then mounts as defined in the spec")
	f.BoolVar(&b.console, "console", false, "set to true if the sandbox should allow terminal ioctl(2) syscalls")
	f.BoolVar(&b.applyCaps, "apply-caps", false, "if true, apply capabilities defined in the spec to the process")
}


// writeSync is used to write to a synchronisation pipe. An error is returned
// if there was a problem writing the payload.
func writeSync(pipe io.Writer) error {
	_, err := pipe.Write([]byte{1})
	return err
}

func readSync(pipe io.Reader) error {
	a := make([]byte, 1)
	_, err := pipe.Read(a)
	return err
}

// syncParentReady sends to the given pipe a JSON payload which indicates that
// the init is ready to Exec the child process. It then waits for the parent to
// indicate that it is cleared to Exec.
func syncParentReady() error {
	envInitPipe  := os.Getenv("_RUNSC_INITPIPE")
	log.Debugf("Syn with parent: pipe %s", envInitPipe)

	pipefd, err := strconv.Atoi(envInitPipe)
	pipe := os.NewFile(uintptr(pipefd), "pipe")

	if err != nil {
		return fmt.Errorf("unable to convert _RUNSC_INITPIPE=%s to int: %s", envInitPipe, err)
	}
	// Tell parent.
	if err := writeSync(pipe); err != nil {
		return err
	}

	log.Debugf("Write to parent...")

	// Wait for parent to give the all-clear.
	if err := readSync(pipe); err != nil {
		return err
	}

	log.Debugf("Read from parent...")

	return nil
}

// Execute implements subcommands.Command.Execute.  It starts a sandbox in a
// waiting state.
func (b *Boot) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if b.bundleDir == "" || b.controllerFD == -1 || f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	// Ensure that if there is a panic, all goroutine stacks are printed.
	debug.SetTraceback("all")

	// Get the spec from the bundleDir.
	spec, err := specutils.ReadSpec(b.bundleDir)
	if err != nil {
		Fatalf("error reading spec: %v", err)
	}

	specutils.LogSpec(spec)

	// Turn any relative paths in the spec to absolute by prepending the bundleDir.
	spec.Root.Path = absPath(b.bundleDir, spec.Root.Path)
	for _, m := range spec.Mounts {
		if m.Source != "" {
			m.Source = absPath(b.bundleDir, m.Source)
		}
	}

	conf := args[0].(*boot.Config)
	waitStatus := args[1].(*syscall.WaitStatus)

	// sentry should run with a umask of 0 when --file-access=direct, because we want
	// to preserve file modes exactly as set by the sentry, which will have applied
	// its own umask.
	if conf.FileAccess == boot.FileAccessDirect {
		syscall.Umask(0)
	}

	if b.applyCaps {
		caps := spec.Process.Capabilities
		if caps == nil {
			caps = &specs.LinuxCapabilities{}
		}
		if conf.Platform == boot.PlatformPtrace {
			// Ptrace platform requires extra capabilities.
			const c = "CAP_SYS_PTRACE"
			caps.Bounding = append(caps.Bounding, c)
			caps.Effective = append(caps.Effective, c)
			caps.Permitted = append(caps.Permitted, c)
		}

		// Remove --apply-caps arg to call myself.
		var args []string
		for _, arg := range os.Args {
			if !strings.Contains(arg, "apply-caps") {
				args = append(args, arg)
			}
		}
		if err := setCapsAndCallSelf(args, caps); err != nil {
			Fatalf("%v", err)
		}
		panic("setCapsAndCallSelf must never return success")
	}

	// sync with create process
	syncParentReady()

	// Create the loader.
	l, err := boot.New(spec, conf, b.controllerFD, b.ioFDs.GetArray(), b.console)
	if err != nil {
		Fatalf("error creating loader: %v", err)
	}

	// Notify other processes the loader has been created.
	l.NotifyLoaderCreated()

	// TODO: change uid and gid
	//if err := Setgid(2000); err != nil {
	//	Fatalf("error set gid: %v", err)
	//}
	//if err := Setuid(2000); err != nil {
	//	Fatalf("error set uid: %v", err)
	//}

	// Wait for the start signal from runsc.
	l.WaitForStartSignal()

	log.Debugf("Start root signal got")

	// Run the application and wait for it to finish.
	if err := l.Run(); err != nil {
		l.Destroy()
		Fatalf("error running sandbox: %v", err)
	}

	ws := l.WaitExit()
	log.Debugf("Root exit: %+v", ws)
	*waitStatus = syscall.WaitStatus(ws.Status())
	l.Destroy()
	return subcommands.ExitSuccess
}

// Setuid sets the uid of the calling thread to the specified uid.
func Setuid(uid int) (err error) {
	_, _, e1 := unix.RawSyscall(unix.SYS_SETUID, uintptr(uid), 0, 0)
	if e1 != 0 {
		err = e1
	}
	return
}

// Setgid sets the gid of the calling thread to the specified gid.
func Setgid(gid int) (err error) {
	_, _, e1 := unix.RawSyscall(unix.SYS_SETGID, uintptr(gid), 0, 0)
	if e1 != 0 {
		err = e1
	}
	return
}

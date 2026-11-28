// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package main

import (
	"context"
	"io"
)

func installAgentService(io.Writer, string, bool) error { return errServiceUnsupported }

func uninstallAgentService(context.Context, io.Writer) error { return errServiceUnsupported }

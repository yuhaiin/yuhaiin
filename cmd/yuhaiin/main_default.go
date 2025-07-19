//go:build !windows && !darwin && (!linux || android)

package main

func install(args []string) error { panic("not implement") }

func uninstall(args []string) error { panic("not implement") }

func restart(args []string) error {
	if err := stop(args); err != nil {
		return err
	}
	return start(args)
}

func stop(args []string) error { panic("not implement") }

func start(args []string) error { panic("not implement") }

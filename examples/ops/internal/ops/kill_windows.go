//go:build windows

package ops

import (
	"os/exec"
	"strconv"
)

// setKillTree 让超时/取消能杀掉整棵进程树。
//
// Windows 没有进程组，用 taskkill /T /F 按 PID 杀树。
func setKillTree(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return exec.Command("taskkill", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F").Run()
	}
}

//go:build !windows

package ops

import (
	"os/exec"
	"syscall"
)

// setKillTree 让超时/取消能杀掉整棵进程树。
//
// 放进独立进程组，超时后 kill -PGID：只杀直接子进程的话，
// 它再拉起的后台进程会变孤儿继续跑。
func setKillTree(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

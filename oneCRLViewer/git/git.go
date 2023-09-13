/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package git

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
)

type Repo struct {
	directory string
}

func NewRepo(directory string) *Repo {
	return &Repo{directory: directory}
}

func (r *Repo) cmd(args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...)
	cmd.Dir = r.directory
	return cmd
}

func (r *Repo) HEAD() (string, error) {
	out, err := r.cmd("rev-parse", "HEAD").CombinedOutput()
	if err != nil {
		return "", errors.New(string(out))
	}
	return string(bytes.TrimSpace(out)), nil
}

func (r *Repo) Add(files ...string) error {
	out, err := r.cmd(append([]string{"add"}, files...)...).CombinedOutput()
	if err != nil {
		return errors.New(string(out))
	}
	return nil
}

func (r *Repo) Commit(message string) error {
	cmd := r.cmd("commit", "-F", "-")
	cmd.Stdin = strings.NewReader(message)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(string(out))
	}
	return nil
}

func (r *Repo) Remote() (string, error) {
	out, err := r.cmd("config", "--get", "remote.origin.url").CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSuffix(out, []byte(".git\n"))), nil
}

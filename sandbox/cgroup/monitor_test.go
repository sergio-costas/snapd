// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2022 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package cgroup_test

import (
	"os"
	"path"
	"time"

	"github.com/snapcore/snapd/sandbox/cgroup"
	. "gopkg.in/check.v1"
)

type monitorSuite struct{}

var _ = Suite(&monitorSuite{})

func (s *monitorSuite) TestMonitorSnapBasicWork(c *C) {
	tmpcontainer := c.MkDir()

	folder1 := path.Join(tmpcontainer, "folder1")
	err := os.Mkdir(folder1, 0755)
	c.Assert(err, IsNil)

	folder2 := path.Join(tmpcontainer, "folder2")
	err = os.Mkdir(folder2, 0755)
	c.Assert(err, IsNil)

	filelist := []string{folder1}

	channel := make(chan string)
	defer close(channel)

	retval := cgroup.MonitorFullDelete("test1", filelist, channel)
	c.Assert(retval, IsNil)

	time.Sleep(1 * time.Second)

	err = os.Remove(folder2)
	c.Assert(err, IsNil)

	// Wait for two seconds to ensure that nothing spurious
	// is received from the channel due to removing folder2
	for i := 0; i < 2; i++ {
		select {
		case <-channel:
			c.Fail()
		case <-time.After(1 * time.Second):
			continue
		}
	}

	err = os.Remove(folder1)
	c.Assert(err, IsNil)
	event := <-channel
	c.Assert(event, Equals, "test1")
}

func (s *monitorSuite) TestMonitorSnapTwoSnapsAtTheSameTime(c *C) {
	tmpcontainer := c.MkDir()

	folder1 := path.Join(tmpcontainer, "folder1")
	err := os.Mkdir(folder1, 0755)
	c.Assert(err, IsNil)

	folder2 := path.Join(tmpcontainer, "folder2")
	err = os.Mkdir(folder2, 0755)
	c.Assert(err, IsNil)

	filelist := []string{folder1, folder2}

	channel := make(chan string)
	defer close(channel)

	retval := cgroup.MonitorFullDelete("test2", filelist, channel)
	c.Assert(retval, Equals, nil)

	time.Sleep(1 * time.Second)

	folder3 := path.Join(tmpcontainer, "folder3")
	err = os.Mkdir(folder3, 0755)
	c.Assert(err, IsNil)

	time.Sleep(1 * time.Second)

	err = os.Remove(folder3)
	c.Assert(err, IsNil)

	// Wait for two seconds to ensure that nothing spurious
	// is received from the channel due to creating or
	// removing folder3
	for i := 0; i < 2; i++ {
		select {
		case <-channel:
			c.Fail()
		case <-time.After(1 * time.Second):
			continue
		}
	}
	err = os.Remove(folder1)
	c.Assert(err, IsNil)
	// Only one file has been removed, so wait two seconds
	// two ensure that nothing spurious is received from
	// the channel
	for i := 0; i < 2; i++ {
		select {
		case <-channel:
			c.Fail()
		case <-time.After(1 * time.Second):
			continue
		}
	}
	err = os.Remove(folder2)
	c.Assert(err, IsNil)

	// All files have been deleted, so NOW we must receive
	// something from the channel
	event := <-channel
	c.Assert(event, Equals, "test2")
}

func (s *monitorSuite) TestMonitorSnapSnapAlreadyStopped(c *C) {
	tmpcontainer := c.MkDir()

	folder1 := path.Join(tmpcontainer, "folder1")

	filelist := []string{folder1}

	channel := make(chan string)
	defer close(channel)

	retval := cgroup.MonitorFullDelete("test3", filelist, channel)
	c.Assert(retval, Equals, nil)
	event := <-channel
	c.Assert(event, Equals, "test3")
}

func (s *monitorSuite) TestMonitorSnapTwoProcessesAtTheSameTime(c *C) {
	tmpcontainer := c.MkDir()

	folder1 := path.Join(tmpcontainer, "folder1")
	err := os.Mkdir(folder1, 0755)
	c.Assert(err, IsNil)

	folder2 := path.Join(tmpcontainer, "folder2")
	err = os.Mkdir(folder2, 0755)
	c.Assert(err, IsNil)

	filelist1 := []string{folder1}
	filelist2 := []string{folder2}

	channel1 := make(chan string)
	defer close(channel1)

	channel2 := make(chan string)
	defer close(channel2)

	retval := cgroup.MonitorFullDelete("test4a", filelist1, channel1)
	c.Assert(retval, Equals, nil)
	retval = cgroup.MonitorFullDelete("test4b", filelist2, channel2)
	c.Assert(retval, Equals, nil)

	time.Sleep(1 * time.Second)

	folder3 := path.Join(tmpcontainer, "folder3")
	err = os.Mkdir(folder3, 0755)
	c.Assert(err, IsNil)

	time.Sleep(1 * time.Second)

	err = os.Remove(folder3)
	c.Assert(err, IsNil)

	// Wait for two seconds to ensure that nothing spurious
	// is received from the channel due to creating or
	// removing folder3
	for i := 0; i < 2; i++ {
		select {
		case <-channel1:
			c.Fail()
		case <-channel2:
			c.Fail()
		case <-time.After(1 * time.Second):
			continue
		}
	}
	err = os.Remove(folder1)
	c.Assert(err, IsNil)
	// Only one file has been removed, so wait two seconds
	// two ensure that nothing spurious is received from
	// the channel
	var receivedEvent = ""
	for i := 0; i < 2; i++ {
		select {
		case receivedEvent = <-channel1:
		case <-channel2:
			c.Fail()
		case <-time.After(1 * time.Second):
			continue
		}
	}
	c.Assert(receivedEvent, Equals, "test4a")
	err = os.Remove(folder2)
	c.Assert(err, IsNil)

	// All files have been deleted, so NOW we must receive
	// something from the channel
	receivedEvent = ""
	for i := 0; i < 2; i++ {
		select {
		case receivedEvent = <-channel2:
		case <-channel1:
			c.Fail()
		case <-time.After(1 * time.Second):
			continue
		}
	}
	c.Assert(receivedEvent, Equals, "test4b")
}

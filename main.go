package main

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
)

/*
1. open and set watcher
2. open file
3. seek to end
4. when event trigger, read all.
*/
func main() {
	secFile := "/var/log/secure"
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
		return
	}

	defer func() {
		err = watcher.Close()
		if err != nil {
			log.Fatal("watcher close failed.", err)
		}
	}()

	fd, err := os.Open(secFile)
	if err != nil {
		log.Fatal("open failed.", err)
	}
	defer func() {
		err = fd.Close()
		if err != nil {
			log.Fatal("close file failed.", err)
		}
	}()

	offset, err := fd.Seek(0, 2)
	if err != nil {
		log.Fatal("seek error", err)
	}
	log.Println("offset: ", offset)

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				log.Println("event:", event)
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Println("modified file:", event.Name)
					// read all
					buf, err := ioutil.ReadAll(fd)
					if err != nil {
						log.Fatal("read file failed.", err)
					}

					// Failed password
					handleNewContent(string(buf))
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add(secFile)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("watcher add succeed.")
	<-done
}

/*
"Failed password.*?from ([0-9.]*?) port"
1. split lines
2. regex match
3.
*/

var pattern = regexp.MustCompile("Failed password.*?from ([0-9.]*?) port")

func handleNewContent(buf string) {
	log.Printf("[%s]\n", buf)
	addrs := extractDenyAddress(buf)
	if len(addrs) == 0 {
		return
	}
	log.Printf("black list: [%v]\n", addrs)

	fd, err := os.OpenFile("/etc/hosts.deny", os.O_RDWR, 0666)
	if err != nil {
		log.Fatal("open hosts deny file failed.", err)
		return
	}
	defer func() {
		err = fd.Close()
		if err != nil {
			log.Fatal("close deny file failed.", err)
		}
	}()

	offset, err := fd.Seek(-1, 2)
	if err != nil {
		log.Fatal("offset deny file failed.", err)
	}
	log.Println("deny offset at", offset)

	var tail = make([]byte, 1)
	_, err = fd.Read(tail)
	if err != nil {
		log.Fatal("read last byte error", err)
	}
	if tail[0] != '\n' {
		_, err = fd.Write([]byte{0x0a})
		if err != nil {
			log.Fatal("write new line to deny file failed.", err)
		}
	}

	for _, addr := range addrs {
		// sshd:115.229.207.143:deny
		line := fmt.Sprintf("sshd:%s:deny\n", addr)
		_, err = fd.Write([]byte(line))
		if err != nil {
			log.Fatal("write deny file failed.", err)
		}
		log.Println("add deny ip addr")
	}
}

func extractDenyAddress(buf string) []string {
	var out []string
	lines := strings.Split(buf, "\n")
	for _, line := range lines {
		rs := pattern.FindStringSubmatch(line)
		if len(rs) != 2 {
			continue
		}
		ipAddr := rs[1]
		out = append(out, ipAddr)
	}

	return out
}

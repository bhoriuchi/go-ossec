package ossec

/*
 * Reference https://www.ossec.net/docs/programs/manage_agents.html
 */

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

var (
	DefaultBinPath = "/var/ossec/bin"
	DefaultTempDir = "/tmp"
	DefaultSSHPort = 22
)

// Client an OSSEC client
type Client struct {
	sshClient  *ssh.Client
	noSudo     bool
	debug      bool
	manageExec string
	tempDir    string
	address    string
	password   string
}

// Options client options
type Options struct {
	BinDir        string
	TempDir       string
	Username      string
	Password      string
	Host          string
	HostKey       string
	Port          int
	NoSudo        bool
	IgnoreHostKey bool
	Debug         bool
}

// Agent an agent entry
type Agent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	IP   string `json:"ip"`
}

// New returns a new ossec client
func New(opts *Options) (*Client, error) {
	if opts.Port == 0 {
		opts.Port = DefaultSSHPort
	}

	if opts.BinDir == "" {
		opts.BinDir = DefaultBinPath
	}

	if opts.TempDir == "" {
		opts.TempDir = DefaultTempDir
	}

	config := &ssh.ClientConfig{
		User: opts.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(opts.Password),
		},
	}

	if opts.HostKey != "" {
		pk, err := ssh.ParsePublicKey([]byte(opts.HostKey))
		if err != nil {
			return nil, err
		}
		config.HostKeyCallback = ssh.FixedHostKey(pk)
	} else if opts.IgnoreHostKey {
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	address := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	sshClient, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return nil, err
	}

	ossec := &Client{
		debug:      opts.Debug,
		sshClient:  sshClient,
		address:    address,
		noSudo:     opts.NoSudo,
		manageExec: filepath.Join(opts.BinDir, "manage_agents"),
		tempDir:    opts.TempDir,
		password:   opts.Password,
	}

	return ossec, nil
}

// Close closes the connection to the session
func (c *Client) Close() error {
	if c.debug {
		fmt.Println("Closing connection to OSSEC server:", c.address)
	}
	return c.sshClient.Close()
}

// runs a command and returns the output
func (c *Client) run(cmd string) (string, error) {
	if c.debug {
		fmt.Println("Executing:", cmd)
	}

	stdoutB := new(bytes.Buffer)
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
	}

	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	err = session.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		return "", err
	}

	session.Stdout = stdoutB
	in, _ := session.StdinPipe()

	go func(in io.Writer, output *bytes.Buffer) {
		for {
			if output != nil {
				if output.Len() > 0 {
					if bytes.Contains(output.Bytes(), []byte("[sudo] password for ")) {
						_, err = in.Write([]byte(c.password + "\n"))
						if err != nil {
							break
						}
						if c.debug {
							fmt.Println("put the password ---  end .")
						}
						break
					}
				}
			}
		}
	}(in, stdoutB)

	if err := session.Run(cmd); err != nil {
		return "", err
	}

	return stdoutB.String(), nil
}

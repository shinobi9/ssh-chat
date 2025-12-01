package sshd

import (
	"net"
	"sync"
	"time"

	"github.com/shazow/rateio"
	"golang.org/x/crypto/ssh"
)

// SSHListener is the container for the connection and ssh-related configuration
type SSHListener struct {
	net.Listener
	config *ssh.ServerConfig

	RateLimit   func() rateio.Limiter
	HandlerFunc func(term *Terminal)

	// handshakeLimit is a semaphore to limit concurrent handshakes globally
	handshakeLimit chan struct{}

	// connLimit tracks concurrent handshakes per IP
	connLimitMutex sync.Mutex
	connLimit      map[string]int
}

// ListenSSH makes an SSH listener socket
func ListenSSH(laddr string, config *ssh.ServerConfig) (*SSHListener, error) {
	socket, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	l := SSHListener{
		Listener:       socket,
		config:         config,
		handshakeLimit: make(chan struct{}, 20),
		connLimit:      make(map[string]int),
	}
	return &l, nil
}

func (l *SSHListener) handleConn(conn net.Conn) (*Terminal, error) {
	if l.RateLimit != nil {
		// TODO: Configurable Limiter?
		conn = ReadLimitConn(conn, l.RateLimit())
	}

	// If the connection doesn't write anything back for too long before we get
	// a valid session, it should be dropped.
	var handleTimeout = 10 * time.Second
	conn.SetReadDeadline(time.Now().Add(handleTimeout))
	defer conn.SetReadDeadline(time.Time{})

	// Upgrade TCP connection to SSH connection
	sshConn, channels, requests, err := ssh.NewServerConn(conn, l.config)
	if err != nil {
		return nil, err
	}

	// FIXME: Disconnect if too many faulty requests? (Avoid DoS.)
	go ssh.DiscardRequests(requests)
	return NewSession(sshConn, channels)
}

// Serve Accepts incoming connections as terminal requests and yield them
func (l *SSHListener) Serve() {
	defer l.Close()
	for {
		conn, err := l.Accept()

		if err != nil {
			logger.Printf("Failed to accept connection: %s", err)
			break
		}

		// Check per-IP limit
		host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			// If we can't parse the IP, we assume it's unique or just let it through to the global limiter
			// but best effort is to log and proceed.
			logger.Printf("Failed to split remote addr: %v", err)
		} else {
			l.connLimitMutex.Lock()
			count := l.connLimit[host]
			if count >= 3 {
				l.connLimitMutex.Unlock()
				logger.Printf("[%s] Rejected connection: too many concurrent handshakes", conn.RemoteAddr())
				conn.Close()
				continue
			}
			l.connLimit[host]++
			l.connLimitMutex.Unlock()
		}

		// Acquire global semaphore
		l.handshakeLimit <- struct{}{}

		// Goroutineify to resume accepting sockets early
		go func() {
			// Ensure limits are released when this goroutine finishes (in case of panic)
			// OR explicitly release them after handshake.
			// Ideally we release them as soon as handshake is done.

			// We need a way to ensure release happens exactly once.
			released := false
			release := func() {
				if released {
					return
				}
				released = true

				// Release global semaphore
				<-l.handshakeLimit

				// Release per-IP limit
				if host != "" {
					l.connLimitMutex.Lock()
					l.connLimit[host]--
					if l.connLimit[host] == 0 {
						delete(l.connLimit, host)
					}
					l.connLimitMutex.Unlock()
				}
			}

			// Defer release in case of panic or early return
			defer release()

			term, err := l.handleConn(conn)

			// Handshake is done (success or failure). Release limits.
			release()

			if err != nil {
				logger.Printf("[%s] Failed to handshake: %s", conn.RemoteAddr(), err)
				conn.Close() // Must be closed to avoid a leak
				return
			}
			l.HandlerFunc(term)
		}()
	}
}

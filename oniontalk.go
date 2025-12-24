package main

import (
    "bufio"
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdh"
    "crypto/rand"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/url"
    "os"
    "os/signal"
    "strings"
    "sync"

    "github.com/awnumar/memguard"
    "golang.org/x/net/proxy"
)

const (
    defaultPort = "8001"
    torProxy    = "socks5://127.0.0.1:9050"
)

var (
    clientConnected = false
    clientMutex     sync.Mutex
)

func main() {
    // Initialize memguard
    memguard.CatchInterrupt()
    defer memguard.Purge()

    sendMode := flag.Bool("s", false, "Run as client (send mode, requires onion address)")
    helpMode := flag.Bool("h", false, "Show help")
    flag.Parse()

    if *helpMode {
        printHelp()
        os.Exit(0)
    }

    args := flag.Args()

    if *sendMode {
        // Client mode (send)
        if len(args) < 1 {
            fmt.Println("Error: Onion address required for client mode")
            fmt.Println()
            printHelp()
            os.Exit(1)
        }
        serverURL := args[0]
        runClient(serverURL)
    } else {
        // Server mode (listen) - no flags needed
        if len(args) > 0 {
            fmt.Println("Error: Unexpected arguments for server mode")
            fmt.Println()
            printHelp()
            os.Exit(1)
        }
        runServer()
    }
}

func printHelp() {
    fmt.Println("OnionTalk - Secure talk sessions over Tor")
    fmt.Println()
    fmt.Println("Usage:")
    fmt.Println("  Listener mode:")
    fmt.Printf("    %s\n", os.Args[0])
    fmt.Println()
    fmt.Println("  Send mode:")
    fmt.Printf("    %s -s <onion-address>\n", os.Args[0])
    fmt.Println()
    fmt.Println("Talk Commands:")
    fmt.Println("  .MULTI  - Start multi-line input")
    fmt.Println("  .END    - Finish multi-line input")
    fmt.Println("  .QUIT   - Exit the program")
}

func runServer() {
    listener, err := net.Listen("tcp", "127.0.0.1:"+defaultPort)
    if err != nil {
        log.Fatalf("Error starting the server: %v", err)
    }
    defer listener.Close()
    fmt.Printf("Listening...\n")

    for {
        conn, err := listener.Accept()
        if err != nil {
            fmt.Printf("Error accepting connection: %v\n", err)
            continue
        }

        clientMutex.Lock()
        if clientConnected {
            clientMutex.Unlock()
            fmt.Println("Connection attempt rejected: Line Busy.")
            handleBusyConnection(conn)
            continue
        }
        clientConnected = true
        clientMutex.Unlock()

        fmt.Println("Client connected.")
        go handleConnection(conn)
    }
}

func handleBusyConnection(conn net.Conn) {
    conn.Write([]byte("Line Busy\n"))
    conn.Close()
}

func runClient(serverURL string) {
    // Add port if not specified - only port 8001 is allowed
    if _, port, err := net.SplitHostPort(serverURL); err != nil {
        // No port specified, add default port
        serverURL = net.JoinHostPort(serverURL, defaultPort)
    } else if port != defaultPort {
        fmt.Printf("Error: Only port %s is allowed. Use: program -s %s\n", defaultPort, serverURL[:len(serverURL)-len(port)-1])
        os.Exit(1)
    }

    torProxyUrl, _ := url.Parse(torProxy)
    dialer, _ := proxy.FromURL(torProxyUrl, proxy.Direct)

    conn, err := dialer.Dial("tcp", serverURL)
    if err != nil {
        fmt.Println("Error connecting to the server:", err)
        return
    }
    defer conn.Close()

    fmt.Println("Connected to the server.")
    performKeyExchange(conn, false)
}

func handleConnection(conn net.Conn) {
    defer func() {
        conn.Close()
        clientMutex.Lock()
        clientConnected = false
        clientMutex.Unlock()
        fmt.Println("Client disconnected.")
    }()

    performKeyExchange(conn, true)
}

func performKeyExchange(conn net.Conn, isServer bool) {
    curve := ecdh.X25519()
    privateKey, err := curve.GenerateKey(rand.Reader)
    if err != nil {
        log.Printf("Error generating private key: %v", err)
        return
    }

    privateKeyBuffer := memguard.NewBufferFromBytes(privateKey.Bytes())
    defer privateKeyBuffer.Destroy()

    publicKey := privateKey.PublicKey()

    // Server receives client's public key first, client sends first
    if isServer {
        clientPublicKeyBytes := make([]byte, 32)
        _, err = io.ReadFull(conn, clientPublicKeyBytes)
        if err != nil {
            log.Printf("Error receiving the client's public key: %v", err)
            return
        }

        clientPublicKey, err := curve.NewPublicKey(clientPublicKeyBytes)
        if err != nil {
            log.Printf("Error parsing the client's public key: %v", err)
            return
        }

        // Send server's public key
        publicKeyBytes := publicKey.Bytes()
        conn.Write(publicKeyBytes)

        sharedSecret, err := privateKey.ECDH(clientPublicKey)
        if err != nil {
            log.Printf("Error calculating the shared secret: %v", err)
            return
        }

        startEncryptedCommunication(conn, sharedSecret, isServer)
    } else {
        // Client sends its public key first
        publicKeyBytes := publicKey.Bytes()
        conn.Write(publicKeyBytes)

        // Receive server's public key
        serverPublicKeyBytes := make([]byte, 32)
        _, err = io.ReadFull(conn, serverPublicKeyBytes)
        if err != nil {
            fmt.Println("Error receiving the server's public key - line busy")
            return
        }

        serverPublicKey, err := curve.NewPublicKey(serverPublicKeyBytes)
        if err != nil {
            fmt.Println("Error parsing the server's public key:", err)
            return
        }

        sharedSecret, err := privateKey.ECDH(serverPublicKey)
        if err != nil {
            fmt.Println("Error calculating the shared secret:", err)
            return
        }

        startEncryptedCommunication(conn, sharedSecret, isServer)
    }
}

func startEncryptedCommunication(conn net.Conn, sharedSecret []byte, isServer bool) {
    sharedSecretBuffer := memguard.NewBufferFromBytes(sharedSecret)
    defer sharedSecretBuffer.Destroy()

    block, err := aes.NewCipher(sharedSecret)
    if err != nil {
        if isServer {
            log.Printf("Error initializing AES cipher: %v", err)
        } else {
            fmt.Println("Error initializing AES cipher:", err)
        }
        return
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        if isServer {
            log.Printf("Error initializing GCM mode: %v", err)
        } else {
            fmt.Println("Error initializing GCM mode:", err)
        }
        return
    }

    var wg sync.WaitGroup
    wg.Add(2)

    go receiveMessages(conn, gcm, &wg, isServer)
    go sendMessages(conn, gcm, &wg, isServer)

    wg.Wait()
}

func receiveMessages(conn net.Conn, gcm cipher.AEAD, wg *sync.WaitGroup, isServer bool) {
    defer wg.Done()
    buf := make([]byte, 4096)
    firstMessage := true
    
    for {
        n, err := conn.Read(buf)
        if err != nil {
            if isServer {
                fmt.Printf("Error reading message: %v\n", err)
            } else {
                fmt.Println("Error reading message:", err)
            }
            return
        }

        decrypted, err := gcm.Open(nil, buf[:12], buf[12:n], nil)
        if err != nil {
            if isServer {
                fmt.Printf("Error decrypting message: %v\n", err)
            } else {
                fmt.Println("Error decrypting message:", err)
            }
            return
        }

        if string(decrypted) == ".QUIT" {
            if isServer {
                clientMutex.Lock()
                clientConnected = false
                clientMutex.Unlock()
            }
            os.Exit(0)
        }

        // Leerzeile vor empfangenen Nachrichten (außer vor der ersten)
        if !firstMessage {
            fmt.Println()  // Leerzeile einfügen
        } else {
            firstMessage = false
        }
        
        fmt.Println(string(decrypted))
    }
}

func sendMessages(conn net.Conn, gcm cipher.AEAD, wg *sync.WaitGroup, isServer bool) {
    defer wg.Done()
    reader := bufio.NewReader(os.Stdin)

    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    go func() {
        <-c
        nonce := make([]byte, 12)
        io.ReadFull(rand.Reader, nonce)
        encrypted := gcm.Seal(nil, nonce, []byte(".QUIT"), nil)
        conn.Write(append(nonce, encrypted...))
        if isServer {
            clientMutex.Lock()
            clientConnected = false
            clientMutex.Unlock()
        }
        os.Exit(0)
    }()

    for {
        // No prompt in normal mode - clean for copy/paste
        input, err := reader.ReadString('\n')
        if err != nil {
            if err == io.EOF {
                // Ctrl+D pressed
                nonce := make([]byte, 12)
                io.ReadFull(rand.Reader, nonce)
                encrypted := gcm.Seal(nil, nonce, []byte(".QUIT"), nil)
                conn.Write(append(nonce, encrypted...))
                os.Exit(0)
            }
            continue
        }

        input = strings.TrimSpace(input)

        if input == ".QUIT" {
            nonce := make([]byte, 12)
            io.ReadFull(rand.Reader, nonce)
            encrypted := gcm.Seal(nil, nonce, []byte(".QUIT"), nil)
            conn.Write(append(nonce, encrypted...))
            if isServer {
                clientMutex.Lock()
                clientConnected = false
                clientMutex.Unlock()
            }
            os.Exit(0)
        }

        if input == ".MULTI" {
            // Multi-line mode - no prompts for clean copy/paste
            var lines []string

            for {
                line, err := reader.ReadString('\n')
                if err != nil {
                    break
                }
                line = strings.TrimSpace(line)

                if line == ".END" {
                    break
                }

                if line == ".QUIT" {
                    nonce := make([]byte, 12)
                    io.ReadFull(rand.Reader, nonce)
                    encrypted := gcm.Seal(nil, nonce, []byte(".QUIT"), nil)
                    conn.Write(append(nonce, encrypted...))
                    os.Exit(0)
                }

                lines = append(lines, line)
            }

            if len(lines) > 0 {
                message := strings.Join(lines, "\n")
                nonce := make([]byte, 12)
                io.ReadFull(rand.Reader, nonce)
                encrypted := gcm.Seal(nil, nonce, []byte(message), nil)
                conn.Write(append(nonce, encrypted...))
            }
            continue
        }

        // Send single line message
        if input != "" {
            nonce := make([]byte, 12)
            io.ReadFull(rand.Reader, nonce)
            encrypted := gcm.Seal(nil, nonce, []byte(input), nil)
            conn.Write(append(nonce, encrypted...))
        }
    }
}
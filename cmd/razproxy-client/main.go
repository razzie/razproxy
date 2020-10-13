package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/razzie/razproxy"
)

// command line args
var (
	ServerAddr    string
	LocalPort     int
	User          string
	Password      string
	SkipTLSVerify bool
)

func init() {
	flag.StringVar(&ServerAddr, "addr", "", "Server address/hostname")
	flag.IntVar(&LocalPort, "port", 1080, "Local SOCKS5 port")
	flag.StringVar(&User, "user", "", "Username for auth")
	flag.StringVar(&Password, "pw", "", "Password for auth")
	flag.BoolVar(&SkipTLSVerify, "skip-tls-verify", false, "Skip TLC cert verification")
	flag.Parse()

	log.SetOutput(os.Stdout)
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	cfg := &razproxy.ClientConfig{
		User:           User,
		Password:       Password,
		SkipCertVerify: SkipTLSVerify,
	}

	if len(os.Args) == 1 {
		cfg.PromptSkipCertVerify = func() bool {
			fmt.Println("Server certificate cannot be verified")
			fmt.Print("Would you like to continue? (y/N): ")
			cont, _, _ := reader.ReadRune()
			return cont == 'y' || cont == 'Y'
		}

		fmt.Print("Server address: ")
		ServerAddr, _ = reader.ReadString('\n')
		ServerAddr = strings.TrimRight(ServerAddr, "\r\n")

		fmt.Print("User (optional): ")
		User, _ = reader.ReadString('\n')
		User = strings.TrimRight(User, "\r\n")
		cfg.User = User

		fmt.Print("Password (optional): ")
		Password, _ = reader.ReadString('\n')
		Password = strings.TrimRight(Password, "\r\n")
		cfg.Password = Password

		fmt.Print("Local SOCKS5 port (1080): ")
		Port, _ := reader.ReadString('\n')
		Port = strings.TrimRight(Port, "\r\n")
		if len(Port) > 0 {
			LocalPort, _ = strconv.Atoi(Port)
		}
	}

	if len(ServerAddr) == 0 {
		ServerAddr = "localhost"
	}

	c, err := razproxy.NewClient(ServerAddr, cfg)
	if err != nil {
		panic(err)
	}

	fmt.Println("Connected")
	if err := c.ListenAndServe(uint16(LocalPort)); err != nil {
		panic(err)
	}
}

package main

import (
	"flag"
	"log"
)

var (
	wgrpcdAddress = flag.String("wgrpcd-address", "localhost:15002", "-wgrpcd-address is the wgrpcd gRPC server on localhost. It must be running to run this program.")
)

func init() {
	flag.Parse()
}

func main() {
	log.Println("wireguardhttps 0.0.1")
	log.Println("This software has not been audited.\nVulnerabilities in this can compromise your server and user data.\nDo not run this in production")

}

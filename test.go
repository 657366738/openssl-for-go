package main

import (
	"log"

	"openssl"
)

func main() {
	//test.Fun1()
	ctx, err := openssl.NewCtx()
	if err != nil {
		log.Fatal(err)
	}
	err = ctx.LoadVerifyLocations("/etc/ssl/certs/ca-certificates.crt", "")
	if err != nil {
		log.Fatal(err)
	}
	//conn, err := openssl.Dial("tcp", "localhost:7777", ctx, 0)
	//println("11111111111111" + conn)
}

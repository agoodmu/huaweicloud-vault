package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/agoodmu/vault-iic/signer"
)

func main() {
	demoAppApigw()
}

func demoAppApigw() {
	s := signer.Signer{
		Key:    os.Getenv("HW_ACCESS_KEY"),
		Secret: os.Getenv("HW_SECRET_KEY"),
	}
	r, err := http.NewRequest("GET", "https://identitycenter.myhuaweicloud.com/v1/instances")
	if err != nil {
		fmt.Println(err)
		return
	}

	r.Header.Add("content-type", "application/json; charset=utf-8")
	s.Sign(r)
	fmt.Println(r.Header)
	client := http.DefaultClient
	resp, err := client.Do(r)
	if err != nil {
		fmt.Println(err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(string(body))
}

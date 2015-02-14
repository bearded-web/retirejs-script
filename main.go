package main

// Temporary file

import (
	"code.google.com/p/go.net/context"
	"github.com/bearded-web/bearded/pkg/script"
	"github.com/davecgh/go-spew/spew"

	"github.com/bearded-web/bearded/pkg/transport/websocket"
	"github.com/bearded-web/retirejs-script/retirejs"
)

func run(addr string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//	transp, err := mango.NewServer(addr)
	transp := websocket.NewServer(addr)
	client, err := script.NewRemoteClient(transp)
	go func() {
		err := transp.Serve(ctx, client)
		if err != nil {
			panic(err)
		}
	}()

	if err != nil {
		panic(err)
	}
	println("wait for connection")
	client.WaitForConnection(ctx)
	println("request config")
	conf, err := client.GetConfig(ctx)
	if err != nil {
		panic(err)
	}

	app := retirejs.New()

	println("handle with conf", spew.Sdump(conf))
	err = app.Handle(ctx, client, conf)
	if err != nil {
		panic(err)
	}
}

func main() {
	//	run("tcp://:9238")
	run(":9238")
}

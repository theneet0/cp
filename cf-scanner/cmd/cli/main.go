package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/radioactiveAHM/cf-scanner/internal/scanner"
	"github.com/schollz/progressbar/v3"
)

func main() {
	confPath := flag.String("c", "conf.json", "Path to configuration JSON file")
	flag.Parse()

	conf, err := scanner.LoadConfig(*confPath)
	if err != nil {
		log.Fatalln(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner := scanner.NewRunner()
	var pbar *progressbar.ProgressBar
	var lastScanned int64

	err = runner.Run(ctx, conf, scanner.Hooks{
		OnProgress: func(p scanner.ProgressEvent) {
			if conf.ProgressBar && p.Total > 0 {
				if pbar == nil {
					pbar = progressbar.Default(p.Total)
				}
				delta := p.Scanned - lastScanned
				if delta > 0 {
					_ = pbar.Add64(delta)
					lastScanned = p.Scanned
				}
			}
		},
		OnLog: func(l scanner.LogEvent) {
			if conf.ProgressBar || !conf.Log {
				return
			}
			switch l.Level {
			case "error":
				color.Red("%s", l.Message)
			case "warn":
				color.Yellow("%s", l.Message)
			case "success":
				color.Green("%s", l.Message)
			default:
				fmt.Println(l.Message)
			}
		},
	})
	if err != nil {
		log.Fatalln(err)
	}
}

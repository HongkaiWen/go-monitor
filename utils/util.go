package utils

import (
	"os"
	"flag"
	"log"
	"runtime/pprof"
)

func Append2File(filename, text string){
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	if _, err = f.WriteString(text); err != nil {
		panic(err)
	}
}

var cpuprofile = flag.String("cpuprofile", "", "Where to write CPU profile")

func Run() func() {
	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatalf("could not open cpu profile file %q", *cpuprofile)
		}
		pprof.StartCPUProfile(f)
		return func() {
			pprof.StopCPUProfile()
			f.Close()
		}
	}
	return func() {}
}

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"magma"
	"os"
	"strconv"
	"time"

	supporting "github.com/jice36/cipher_support"
)



var CheckSum string

type paths struct {
	inputFile  string
	outputFile string
}

var keyСhangeIn int
var logger *log.Logger
var l *os.File

func main() {
	if len(os.Args) == 0 {
		return
	}
	var err error

	str, t := timeTest("test rotateKey = " + os.Args[5])

	logger, l = supporting.CreateLogger(logger)
	checkMagma := make(chan error)
	CheckSum, err = supporting.BegincheckSum()
	switch os.Args[1] {
	case "e":
		f1 := &paths{os.Args[2], os.Args[3]}
		count, err := strconv.Atoi(os.Args[5])
		err = f1.encrypt(magma.PasswordToKey([]byte(os.Args[4])), uint32(magma.RotateKeyCounter(count)), checkMagma)
		logger.Println(err)
	case "d":
		f1 := &paths{os.Args[2], os.Args[3]}
		count, err := strconv.Atoi(os.Args[5])
		err = f1.decrypt(magma.PasswordToKey([]byte(os.Args[4])), uint32(magma.RotateKeyCounter(count)), checkMagma)
		logger.Println(err)
	default:
		fmt.Println("wrong mode")
	}
	logger.Println(err)
	defer func() {
		testing(str, t)
		defer l.Close()
	}()

}

func timeTest(test string) (string, time.Time) {
	return test, time.Now()
}

func testing(test string, start time.Time) {
	logger.Printf("шифруемый файл - "+os.Args[2]+" Прошло %s = %v \n", test, time.Since(start).Minutes())
}

func (p *paths) encrypt(key []byte, count uint32, checkMagma chan error) error {
	data := make([]byte, 8)
	rc := make([]byte, 8)
	iv := magma.GenIV()
	var c uint32 // счетчик

	i, err := os.Open(p.inputFile)
	if err != nil {
		return err
	}
	defer i.Close()
	//defer os.Remove(p.inputFile)

	o, err := os.Create(p.outputFile)
	if err != nil {
		return err
	}
	defer o.Close()

	s, err := magma.GenSubKeys(key)
	if err != nil {
		return err
	}

	r := bufio.NewReader(i)
	w := bufio.NewWriter(o)

	fiv, err := os.Create(p.outputFile + "iv")
	if err != nil {
		return err
	}
	defer fiv.Close()
	wiv := bufio.NewWriter(fiv)

	err = writeBlock(wiv, iv)
	for {
		data, err := readBlock(r, data, false)

		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if count == c {
			go supporting.CheckSum(checkMagma, CheckSum)
			key, err = magma.ChangeOldKeyToNewKey(key)
			if err != nil {
				return err
			}
			s, err = magma.GenSubKeys(key)
			if err != nil {
				return nil
			}
			check := <-checkMagma
			if check != nil {
				return check
			}
		}

		s, rc, err = magma.RoundCipher(s, data, iv, c)
		if err != nil {
			return err
		}
		err = writeBlock(w, rc)

		if err != nil {
			return err
		}
		c++
	}
	defer s.ClearingMemory()
	return nil
}

func (p *paths) decrypt(key []byte, count uint32, checkMagma chan error) error {
	data := make([]byte, 8)
	rc := make([]byte, 8)
	iv := make([]byte, 4)
	var c uint32

	i, err := os.Open(p.inputFile)
	if err != nil {
		return err
	}
	defer i.Close()

	o, err := os.Create(p.outputFile)
	if err != nil {
		return err
	}
	defer o.Close()

	s, err := magma.GenSubKeys(key)
	if err != nil {
		return err
	}

	r := bufio.NewReader(i)
	w := bufio.NewWriter(o)

	fiv, err := os.Open(p.inputFile + "iv")
	if err != nil {
		return err
	}
	defer fiv.Close()
	riv := bufio.NewReader(fiv)
	defer os.Remove(p.inputFile + "iv")

	iv, err = readBlock(riv, iv, true)
	for {
		data, err := readBlock(r, data, false)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if count == c {
			go supporting.CheckSum(checkMagma, CheckSum)
			key, err = magma.ChangeOldKeyToNewKey(key)
			if err != nil {
				return err
			}
			s, err = magma.GenSubKeys(key)
			if err != nil {
				return nil
			}
			check := <-checkMagma
			if check != nil {
				return check
			}
		}
		s, rc, err = magma.RoundCipher(s, data, iv, c)
		if err != nil {
			return err
		}
		err = writeBlock(w, nullByte(rc))
		if err != nil {
			return err
		}
		c++
	}
	defer s.ClearingMemory()
	return nil
}

// отбрасывание нулевых байт при расширофвании
func nullByte(data []byte) []byte {
	if data[7] != 0 {
		return data
	} else {
		j := 1
		for i := 6; i > 1; i-- {
			if data[i] == 0 {
				j++
			}
		}
		return data[:8-j]
	}
}

func readBlock(r *bufio.Reader, block []byte, readiv bool) ([]byte, error) {
	num, err := r.Read(block)
	if err != nil {
		return nil, err
	}
	if readiv {
		return block, nil
	}
	if num != 8 {
		for i := num; i < 8; i++ {
			block[i] = 0
		}
	}
	return block, err
}

func writeBlock(w *bufio.Writer, block []byte) error {
	_, err := w.Write(block)
	if err != nil {
		return err
	}
	w.Flush()
	return nil
}


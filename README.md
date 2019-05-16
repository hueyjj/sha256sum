# sha256sum
Hash a file using the SHA-256 algorithm.

I don't know why but it's not hashing multiple chunks correctly. If the file size is less than 512 bit it will work though. 
Just need to figure out why it doesn't for > 512 bit files....

# Quick start
```bash
$ go get github.com/hueyjj/sha256sum
$ cd $GOPATH/src/github.com/hueyjj/sha256sum
$ go test
```
```go
import (
    github.com/hueyjj/sha256sum
)

func main() {
	fmt.Println(Sha256Sum("./somefilehere"))
}
```
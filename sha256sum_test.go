package sha256sum

import (
	"fmt"
	"testing"
)

func TestSha256Sum(t *testing.T) {
	//fmt.Println(Sha256Sum("C:/Users/Jasper/Downloads/video.mkv"))
	// fmt.Println(Sha256Sum("./abc"))
	fmt.Println(Sha256Sum("./foo"))
	// fmt.Println(Sha256Sum("./sha256sum.go"))
}

package sha256sum

import (
	"fmt"
	"testing"
)

func TestSha256Sum(t *testing.T) {
	fmt.Println(Sha256Sum("abc"))
	fmt.Println(Sha256Sum(""))
	fmt.Println(Sha256Sum("."))
	fmt.Println(Sha256Sum("JasperJeng"))
}

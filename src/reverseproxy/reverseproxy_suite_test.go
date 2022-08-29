package reverseproxy_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestReverseproxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Reverseproxy Suite")
}

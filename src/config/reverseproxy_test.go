package config_test

import (
	"context"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sdc-wob-type-3/Vanguard-mTLS-safari/tls-reverse-proxy/config"
	"os"
)

var _ = Describe("Config", func() {
	for _, scenario := range []struct {
		name   string
		given  func()
		expect func(config config.Config, err error)
	}{
		{
			name:  "without CERT_INTERVAL",
			given: func() {},
			expect: func(config config.Config, err error) {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("interval to refresh certificate missing, please provide CERT_INTERVAL"))
			},
		},
		{
			name: "without a valid CERT_INTERVAL",
			given: func() {
				Expect(os.Setenv("CERT_INTERVAL", "INVALID")).To(BeNil())
			},
			expect: func(config config.Config, err error) {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("time: invalid duration \"INVALID\""))
			},
		},
		{
			name: "without a port",
			given: func() {
				Expect(os.Setenv("CERT_INTERVAL", "1s")).To(BeNil())
			},
			expect: func(config config.Config, err error) {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("port is missing, please provide PORT"))
			},
		},
		{
			name: "without a proxy target",
			given: func() {
				Expect(os.Setenv("CERT_INTERVAL", "1s")).To(BeNil())
				Expect(os.Setenv("PORT", "2")).To(BeNil())
			},
			expect: func(config config.Config, err error) {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("reverse proxy target is missing, please provide PROXY_TARGET"))
			},
		},
		{
			name: "without a valid proxy target",
			given: func() {
				Expect(os.Setenv("CERT_INTERVAL", "1s")).To(BeNil())
				Expect(os.Setenv("PORT", "2")).To(BeNil())
				Expect(os.Setenv("PROXY_TARGET", "invalid")).To(BeNil())
			},
			expect: func(config config.Config, err error) {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("parse \"invalid\": invalid URI for request"))
			},
		},
		{
			name: "without a domain",
			given: func() {
				Expect(os.Setenv("CERT_INTERVAL", "1s")).To(BeNil())
				Expect(os.Setenv("PORT", "2")).To(BeNil())
				Expect(os.Setenv("PROXY_TARGET", "http://localhost")).To(BeNil())
			},
			expect: func(config config.Config, err error) {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("reverse proxy domain is missing, please provide DOMAIN"))
			},
		},
	} {
		It(scenario.name, func() {
			defer func() {
				Expect(os.Unsetenv("CERT_INTERVAL")).To(BeNil())
				Expect(os.Unsetenv("PORT")).To(BeNil())
				Expect(os.Unsetenv("PROXY_TARGET")).To(BeNil())
				Expect(os.Unsetenv("DOMAIN")).To(BeNil())
			}()
			scenario.given()
			scenario.expect(config.Init(context.Background()))
		})
	}
})

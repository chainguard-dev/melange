// Copyright 2022 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/chainguard-dev/clog"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type KeygenContext struct {
	KeyName string
	BitSize int
}

func (kc *KeygenContext) GenerateKeypair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, kc.BitSize)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate RSA private key: %w", err)
	}

	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

func keygen() *cobra.Command {
	var keySize int
	cmd := &cobra.Command{
		Use:     "keygen",
		Short:   "Generate a key for package signing",
		Long:    `Generate a key for package signing.`,
		Example: `  melange keygen [key.rsa]`,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := "melange.rsa"
			if len(args) > 0 {
				name = args[0]
			}
			return KeygenCmd(cmd.Context(), name, keySize)
		},
	}
	cmd.Flags().IntVar(&keySize, "key-size", 4096, "the size of the prime to calculate (in bits)")
	return cmd
}

func KeygenCmd(ctx context.Context, keyName string, bitSize int) error {
	log := clog.FromContext(ctx)

	if bitSize < 2048 {
		return errors.New("key size is less than 2048 bits, this is not considered safe")
	}

	kc := &KeygenContext{
		KeyName: keyName,
		BitSize: bitSize,
	}

	log.Infof("generating keypair with a %d bit prime, please wait...", kc.BitSize)

	privkey, pubkey, err := kc.GenerateKeypair()
	if err != nil {
		return err
	}

	privateKeyData := x509.MarshalPKCS1PrivateKey(privkey)
	privateKeyBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyData,
	}
	privatePem, err := os.Create(kc.KeyName)
	if err != nil {
		return fmt.Errorf("unable to open private key for writing: %w", err)
	}
	defer privatePem.Close()

	if err := pem.Encode(privatePem, &privateKeyBlock); err != nil {
		return fmt.Errorf("unable to encode private key: %w", err)
	}

	log.Infof("wrote private key to %s", privatePem.Name())

	publicKeyData, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return fmt.Errorf("unable to calculate public key: %w", err)
	}
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyData,
	}
	publicPem, err := os.Create(fmt.Sprintf("%s.pub", kc.KeyName))
	if err != nil {
		return fmt.Errorf("unable to open public key for writing: %w", err)
	}
	defer publicPem.Close()

	if err := pem.Encode(publicPem, &publicKeyBlock); err != nil {
		return fmt.Errorf("unable to encode public key: %w", err)
	}

	log.Infof("wrote public key to %s", publicPem.Name())

	return nil
}

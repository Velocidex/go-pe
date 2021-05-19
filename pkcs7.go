package pe

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"

	"github.com/Velocidex/pkcs7"
)

// Reference https://datatracker.ietf.org/doc/html/rfc2315
var (
	OIDIndirectData     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	OIDCounterSignature = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
)

type SpcString struct {
	Unicode []byte `asn1:"tag:0"`
}

type SpcPeImageData struct {
	Flags asn1.BitString
	File  asn1.RawValue
}

type SpcAttributeTypeAndOptionalValue struct {
	Type  asn1.ObjectIdentifier
	Value SpcPeImageData
}

type AlgorithmIdentifier struct {
	Type asn1.ObjectIdentifier
}

type DigestInfo struct {
	DigestAlgorithm pkix.AlgorithmIdentifier
	Digest          []byte
}

type SpcIndirectDataContent struct {
	Data          SpcAttributeTypeAndOptionalValue
	MessageDigest DigestInfo
}

func parseIndirectData(pkcs7 *pkcs7.PKCS7) *SpcIndirectDataContent {
	var indirect_data SpcIndirectDataContent
	_, err := asn1.Unmarshal(pkcs7.SignedData.ContentInfo.Content.Bytes, &indirect_data)
	if err == nil {
		return &indirect_data
	}

	return nil
}

type spcSpOpusInfo struct {
	ProgramName asn1.RawValue `asn1:"explicit,optional,tag:0"`
	MoreInfo    asn1.RawValue `asn1:"explicit,optional,tag:1"`
}

type spcString struct {
	Value asn1.RawValue
}

type SpcSpOpusInfo struct {
	ProgramName string
	MoreInfo    string
}

func decodeSpcString(value asn1.RawValue) string {
	var result asn1.RawValue
	switch value.Tag {
	case 0, 1:
		asn1.Unmarshal(value.Bytes, &result)
		return string(result.Bytes)
	default:
		return ""
	}
}

func parseSpcSpOpusInfo(bytes []byte) *SpcSpOpusInfo {
	var data spcSpOpusInfo
	_, err := asn1.Unmarshal(bytes, &data)
	if err == nil {
		// Since SpcString is a choice we need to decode it by
		// hand.
		return &SpcSpOpusInfo{
			ProgramName: decodeSpcString(data.ProgramName),
			MoreInfo:    decodeSpcString(data.MoreInfo),
		}
	}
	return nil
}

func getHashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, string, error) {
	switch {
	case oid.Equal(pkcs7.OIDDigestAlgorithmSHA1),
		oid.Equal(pkcs7.OIDDigestAlgorithmECDSASHA1),
		oid.Equal(pkcs7.OIDDigestAlgorithmDSA),
		oid.Equal(pkcs7.OIDDigestAlgorithmDSASHA1),
		oid.Equal(pkcs7.OIDEncryptionAlgorithmRSA):
		return crypto.SHA1, "SHA1", nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmSHA256),
		oid.Equal(pkcs7.OIDDigestAlgorithmECDSASHA256):
		return crypto.SHA256, "SHA256", nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmSHA384),
		oid.Equal(pkcs7.OIDDigestAlgorithmECDSASHA384):
		return crypto.SHA384, "SHA384", nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmSHA512),
		oid.Equal(pkcs7.OIDDigestAlgorithmECDSASHA512):
		return crypto.SHA512, "SHA512", nil
	}
	return crypto.Hash(0), "Unknown", errors.New("Unsupported")
}

func parseTimestamp(bytes []byte) *time.Time {
	var result time.Time
	_, err := asn1.Unmarshal(bytes, &result)
	if err == nil {
		return &result
	}
	return nil
}

func parseMessageDigest(bytes []byte) []byte {
	var result []byte
	asn1.Unmarshal(bytes, &result)
	return result
}

func parseCounterSignature(bytes []byte) *pkcs7.SignerInfo {
	var result pkcs7.SignerInfo
	_, err := asn1.Unmarshal(bytes, &result)
	if err == nil {
		return &result
	}
	return nil
}

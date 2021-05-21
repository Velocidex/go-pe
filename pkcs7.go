package pe

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/pkcs7"
	"golang.org/x/text/encoding/unicode"
)

type SpcString struct {
	Unicode []byte `asn1:"tag:0"`
}

type SpcPeImageData struct {
	Flags asn1.BitString
	//	Flags []asn1.RawValue `asn1:"tag:0,optional"`
	File asn1.RawValue
}

type SpcAttributeTypeAndOptionalValue struct {
	Type  asn1.ObjectIdentifier
	Value SpcPeImageData `asn1:"tag:2,optional"`
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

func parseIndirectData(pkcs7 *pkcs7.PKCS7) (*SpcIndirectDataContent, error) {
	var indirect_data SpcIndirectDataContent
	_, err := asn1.Unmarshal(pkcs7.SignedData.ContentInfo.Content.Bytes, &indirect_data)
	if err != nil {
		return nil, err
	}

	return &indirect_data, nil
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

func UTF16ToString(in []byte) string {
	decoder := unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM).NewDecoder()
	utf8, err := decoder.Bytes(in)
	if err != nil {
		return string(in)
	}
	return string(utf8)
}

func UTF16ToStringLE(in []byte) string {
	decoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
	utf8, err := decoder.Bytes(in)
	if err != nil {
		return string(in)
	}
	return string(utf8)
}

func decodeSpcString(value asn1.RawValue) string {
	var result asn1.RawValue
	asn1.Unmarshal(value.Bytes, &result)

	// This does not appear very consistent in practice so we just
	// guess if it is unicode or utf8.
	if len(result.Bytes) > 0 && len(result.Bytes)%2 == 0 && result.Bytes[0] == 0 {
		return UTF16ToString(result.Bytes)
	}
	return string(result.Bytes)
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

func getContentTypeString(bytes []byte) string {
	var oid asn1.ObjectIdentifier
	asn1.Unmarshal(bytes, &oid)

	switch {
	case oid.Equal(oidCertificateTrustList):
		return fmt.Sprintf("Certificate Trust List")
	default:
		return fmt.Sprintf("%v", oid)
	}
}

type OIDSequence struct {
	Type asn1.ObjectIdentifier
}

func (self OIDSequence) Equal(in asn1.ObjectIdentifier) bool {
	return self.Type.Equal(in)
}

type OIDWithParamers struct {
	Type   asn1.ObjectIdentifier
	Params asn1.RawValue `asn1:"set,optional"`
}

func (self OIDWithParamers) Equal(in asn1.ObjectIdentifier) bool {
	return self.Type.Equal(in)
}

// A hash descriptor for a file or cab in the catalog
type CabHash struct {
	Type   OIDSequence
	Digest []byte
}

type KV struct {
	Type  OIDSequence
	Value asn1.RawValue `asn1:"optional"`
}

func (self KV) Walk(out *ordereddict.Dict) {
	if self.Value.Bytes == nil {
		return
	}

	switch {
	case self.Type.Equal(OIDSPC_CAB_DATA_OBJID), self.Type.Equal(OIDSPC_PE_IMAGE_DATA_OBJID):
		var hash_info CabHash
		_, err := asn1.Unmarshal(self.Value.FullBytes, &hash_info)
		if err != nil {
			return
		}

		_, hash, _ := getHashForOID(hash_info.Type.Type)
		out.Set("HashType", hash)
		out.Set("Hash", fmt.Sprintf("%x", hash_info.Digest))

	default:
		Debug(self)
	}
}

// Arbitrary kv string with metadata
type KVString struct {
	Key     string
	Unknown int
	Value   []byte
}

type CatalogMemberSet struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"optional"`
}

func (self CatalogMemberSet) Walk(out *ordereddict.Dict) {
	if self.Value.FullBytes == nil {
		return
	}

	switch {
	case self.Type.Equal(OIDCAT_MEMBERINFO2_OBJID), self.Type.Equal(OIDCAT_MEMBERINFO_OBJID):
	case self.Type.Equal(OIDNameValueObjId):
		var nameValue KVString
		_, err := asn1.Unmarshal(self.Value.Bytes, &nameValue)
		if err != nil {
			Debug(err)
			return
		}
		filename := UTF16ToStringLE(nameValue.Value)
		filename = strings.TrimSuffix(filename, "\x00")
		out.Set(nameValue.Key, filename)

	case self.Type.Equal(OIDIndirectData):
		var kv KV
		_, err := asn1.Unmarshal(self.Value.Bytes, &kv)
		if err != nil {
			Debug(err)
			return
		}

		kv.Walk(out)
	default:
		Debug(self)
	}
}

type CatalogList struct {
	Digest  []byte
	Members []asn1.RawValue `asn1:"set,optional"`
}

func (self CatalogList) Walk(out *ordereddict.Dict) {
	for _, raw_member := range self.Members {
		var member CatalogMemberSet
		_, err := asn1.Unmarshal(raw_member.FullBytes, &member)
		if err != nil {
			Debug(err)
			continue
		}
		member.Walk(out)
	}
}

type NameValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

func (self NameValue) Walk(out *ordereddict.Dict) {
	if self.Value.Bytes == nil {
		return
	}

	switch {
	case self.Type.Equal(OIDNameValueObjId):
		var nameValue KVString
		_, err := asn1.Unmarshal(self.Value.Bytes, &nameValue)
		if err != nil {
			Debug(err)
			return
		}
		filename := UTF16ToStringLE(nameValue.Value)
		filename = strings.TrimSuffix(filename, "\x00")
		out.Set(nameValue.Key, filename)
	}
}

type CatNameValue struct {
	Items []NameValue
}

func (self CatNameValue) Walk(out *ordereddict.Dict) {
	for _, item := range self.Items {
		item.Walk(out)
	}
}

type CertificateTrustList struct {
	Type         OIDSequence
	Digest       []byte
	Time         time.Time
	MemberOID    OIDSequence
	CatalogList  []CatalogList
	CatNameValue CatNameValue `asn1:"tag:0"`
}

// CTLs are stored in catalog .cat files.
func parseCertificateTrustList(pkcs7 *pkcs7.PKCS7, result *ordereddict.Dict) {
	var ctl CertificateTrustList
	_, err := asn1.Unmarshal(pkcs7.SignedData.ContentInfo.Content.Bytes, &ctl)
	if err != nil {
		Debug(err)
		return
	}

	var ctl_set []*ordereddict.Dict

	for _, item := range ctl.CatalogList {
		item_dict := ordereddict.NewDict().
			Set("Hash", fmt.Sprintf("%x", item.Digest))
		ctl_set = append(ctl_set, item_dict)

		// Walk the ASN.1 struct and parse out interesting fields
		item.Walk(item_dict)
	}

	ctl.CatNameValue.Walk(result)

	result.Set("CertificateTrustList", ctl_set)
}

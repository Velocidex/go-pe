package pe

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"sort"
	"strings"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/pkcs7"
)

const (
	IMAGE_DIRECTORY_ENTRY_SECURITY = 4
)

var (
	oidEmailAddress                 = []int{1, 2, 840, 113549, 1, 9, 1}
	oidExtensionAuthorityInfoAccess = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidNSComment                    = []int{2, 16, 840, 1, 113730, 1, 13}
	oidPostalCode                   = []int{2, 5, 4, 17}
	oidSerialNumber                 = []int{2, 5, 4, 5}

	oidSoftwarePublisher = []int{1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 3, 2}
	oidCodeSigning       = []int{2, 23, 140, 1, 4, 1}
	oidAnyPolicy         = []int{2, 5, 29, 32, 0}
	oidTimestampCert     = []int{1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 3, 8}

	oidContentType              = []int{1, 2, 840, 113549, 1, 9, 3}
	oidSigningTime              = []int{1, 2, 840, 113549, 1, 9, 5}
	oidSPC_STATEMENT_TYPE_OBJID = []int{1, 3, 6, 1, 4, 1, 311, 2, 1, 11}
	oidMessageDigest            = []int{1, 2, 840, 113549, 1, 9, 4}
	oidSPC_SP_OPUS_INFO_OBJID   = []int{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	OIDSPC_PE_IMAGE_DATA_OBJID  = []int{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}

	oidCertificateTrustList = []int{1, 3, 6, 1, 4, 1, 311, 10, 1}

	// Reference https://datatracker.ietf.org/doc/html/rfc2315
	OIDIndirectData            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	OIDSPC_CAB_DATA_OBJID      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 25}
	OIDCounterSignature        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	OIDCatalogList             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 1, 1}
	OIDCAT_MEMBERINFO_OBJID    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 2, 2}
	OIDCAT_MEMBERINFO2_OBJID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 2, 3}
	OIDNameValueObjId          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 2, 1}
	OID_CATALOG_LIST_MEMBER_V2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 1, 3}
)

func (self *IMAGE_NT_HEADERS) ParseSecurityInfo() (*pkcs7.PKCS7, error) {
	dir := self.DataDirectory(IMAGE_DIRECTORY_ENTRY_SECURITY)
	if dir.DirSize() == 0 {
		// No Export Directory
		return nil, errors.New("No IMAGE_DIRECTORY_ENTRY_SECURITY defined")
	}

	// This is really a file offset and not a virtual offset at all!
	win_cert := self.Profile.WIN_CERTIFICATE(self.Reader, int64(dir.VirtualAddress()))

	data := make([]byte, CapUint32(win_cert.Length(), MAX_WIN_CERTIFICATE_LENGTH))
	_, err := win_cert.Reader.ReadAt(data, int64(win_cert.Offset+8))
	if err != nil {
		return nil, err
	}

	pkcs7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	return pkcs7, nil
}

type Hashes struct {
	MD5    hash.Hash
	SHA1   hash.Hash
	SHA256 hash.Hash
}

func (self *PEFile) CalcHashToDict() *ordereddict.Dict {
	hashes := self.CalcHash()
	md5_hex := fmt.Sprintf("%0x", hashes.MD5.Sum(nil))
	sha1_hex := fmt.Sprintf("%0x", hashes.SHA1.Sum(nil))
	sha256_hex := fmt.Sprintf("%0x", hashes.SHA256.Sum(nil))

	result := ordereddict.NewDict().
		Set("MD5", md5_hex).
		Set("SHA1", sha1_hex).
		Set("SHA256", sha256_hex)

	var hash_matches bool
	authenticode_info, err := ParseAuthenticode(self)
	if err == nil {
		indirect_data, err := parseIndirectData(authenticode_info)
		if err != nil {
			return result
		}

		expected_hash := fmt.Sprintf("%0x", indirect_data.MessageDigest.Digest)
		_, hash, _ := getHashForOID(indirect_data.MessageDigest.DigestAlgorithm.Algorithm)
		switch hash {
		case "MD5":
			hash_matches = expected_hash == md5_hex

		case "SHA1":
			hash_matches = expected_hash == sha1_hex
		case "SHA256":
			hash_matches = expected_hash == sha256_hex
		}
	}
	result.Set("HashMatches", hash_matches)

	return result
}

// Hashing algorithm description in "Windows Authenticode Portable Executable Signature Format" http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx
func (self *PEFile) CalcHash() *Hashes {
	hasher := &Hashes{
		MD5:    md5.New(),
		SHA1:   sha1.New(),
		SHA256: sha256.New(),
	}

	start_of_checksum := self.nt_header.OptionalHeader().Offset +
		self.nt_header.Profile.Off_IMAGE_OPTIONAL_HEADER_CheckSum

	security_dir := self.nt_header.DataDirectory(IMAGE_DIRECTORY_ENTRY_SECURITY)

	writer := io.MultiWriter(hasher.MD5, hasher.SHA1, hasher.SHA256)

	wrapper := NewReaderWrapper(self.dos_header.Reader)
	DebugPrint("First range %d-%d\n", self.dos_header.Offset, start_of_checksum)
	wrapper.CopyRange(writer, self.dos_header.Offset, start_of_checksum)

	DebugPrint("Second range %d-%d\n", start_of_checksum+4, security_dir.Offset)
	wrapper.CopyRange(writer, start_of_checksum+4, security_dir.Offset)

	optional_header := self.nt_header.OptionalHeader()

	// The SizeOfHeaders is the end of the entire first part of
	// the file (including all headers). After that there are sections.
	wrapper.CopyRange(writer, security_dir.Offset+8,
		int64(optional_header.SizeOfHeaders()))
	DebugPrint("range %d-%d\n",
		security_dir.Offset+8, int64(optional_header.SizeOfHeaders()))

	// Sort the sections in ascending file offset order.
	sections := self.nt_header.Sections()
	sort.Slice(sections, func(i, j int) bool {
		return sections[i].PointerToRawData() < sections[j].PointerToRawData()
	})

	// Write the sections into the hash
	for _, section := range sections {
		// Skip empty sections.
		if section.SizeOfRawData() == 0 {
			continue
		}

		start := int64(section.PointerToRawData())
		end := start + int64(section.SizeOfRawData())

		DebugPrint("Section %v from %d-%d\n", section.Name(), start, end)
		wrapper.CopyRange(writer, start, end)
	}

	return hasher
}

func ParseAuthenticode(pe *PEFile) (*pkcs7.PKCS7, error) {
	return pe.nt_header.ParseSecurityInfo()
}

// Builds a Dict with information about the PKCS7 structure. This can
// be consumed by callers who just want to show information about the
// PKCS7.
func PKCS7ToOrderedDict(self *pkcs7.PKCS7) *ordereddict.Dict {
	certificates := make([]*ordereddict.Dict, 0, len(self.Certificates))
	for _, cert := range self.Certificates {
		certificates = append(certificates, X509ToOrderedDict(cert))
	}

	result := ordereddict.NewDict().
		Set("Signer", getSigner(self)).
		Set("Certificates", certificates)

	getSignedData(self, result)

	return result
}

type rawCertificates struct {
	Certificates []x509.Certificate `asn1:""`
}

func getSignedData(pkcs7 *pkcs7.PKCS7, result *ordereddict.Dict) {
	if pkcs7.SignedData.ContentInfo.ContentType.Equal(OIDIndirectData) {
		indirect_data, err := parseIndirectData(pkcs7)
		if indirect_data != nil && err == nil {
			_, hash, _ := getHashForOID(indirect_data.MessageDigest.DigestAlgorithm.Algorithm)

			result.Set("HashType", hash)
			result.Set("ExpectedHash", indirect_data.MessageDigest.Digest)
			result.Set("ExpectedHashHex", fmt.Sprintf("%x", indirect_data.MessageDigest.Digest))
		}
	} else if pkcs7.SignedData.ContentInfo.ContentType.Equal(oidCertificateTrustList) {
		parseCertificateTrustList(pkcs7, result)
	}
}

func getSignerInfo(signer_info *pkcs7.SignerInfo) *ordereddict.Dict {
	var tmp []asn1.RawValue
	_, err := asn1.Unmarshal(signer_info.IssuerAndSerialNumber.IssuerName.FullBytes, &tmp)
	if err != nil {
		return nil
	}

	var names []pkix.AttributeTypeAndValue
	for _, name := range tmp {
		var parsed_name pkix.AttributeTypeAndValue
		_, err := asn1.Unmarshal(name.Bytes, &parsed_name)
		if err != nil {
			Debug(err)
		} else {
			names = append(names, parsed_name)
		}
	}

	_, hash_name, _ := getHashForOID(signer_info.DigestAlgorithm.Algorithm)

	signer := ordereddict.NewDict().
		Set("IssuerName", getNamesString(names)).
		Set("SerialNumber", fmt.Sprintf("%x", signer_info.IssuerAndSerialNumber.SerialNumber)).
		Set("DigestAlgorithm", hash_name)

	authenticated_attributes := ordereddict.NewDict()
	for _, attr := range signer_info.AuthenticatedAttributes {
		if attr.Type.Equal(oidSPC_SP_OPUS_INFO_OBJID) {
			program_info := parseSpcSpOpusInfo(attr.Value.Bytes)
			authenticated_attributes.
				Set("ProgramName", program_info.ProgramName).
				Set("MoreInfo", program_info.MoreInfo)
		} else if attr.Type.Equal(oidSPC_STATEMENT_TYPE_OBJID) {

		} else if attr.Type.Equal(oidSigningTime) {
			authenticated_attributes.
				Set("SigningTime", parseTimestamp(attr.Value.Bytes))

		} else if attr.Type.Equal(oidMessageDigest) {
			md := parseMessageDigest(attr.Value.Bytes)
			authenticated_attributes.
				Set("MessageDigest", md).
				Set("MessageDigestHex", fmt.Sprintf("%x", md))
		} else if attr.Type.Equal(oidContentType) {
			authenticated_attributes.
				Set("ContentType", getContentTypeString(attr.Value.Bytes))
		} else {
			authenticated_attributes.
				Set(fmt.Sprintf("Oid: %v", attr.Type), "Unknown")
		}
	}
	signer.Set("AuthenticatedAttributes", authenticated_attributes)

	unauthenticated_attributes := ordereddict.NewDict()
	for _, attr := range signer_info.UnauthenticatedAttributes {
		if attr.Type.Equal(OIDCounterSignature) {

			unauthenticated_attributes.
				Set("CounterSignature", getSignerInfo(parseCounterSignature(attr.Value.Bytes)))
		}
	}
	signer.Set("UnauthenticatedAttributes", unauthenticated_attributes)

	return signer
}

// Authenticode has only one signer - the signer info indicates a
// certificate serial number which should refer to one of the
// certificates in the pkcs7 structure.
func getSigner(self *pkcs7.PKCS7) *ordereddict.Dict {
	for _, signer_info := range self.Signers {
		// Now try to find the correct certificate
		serial_number := signer_info.IssuerAndSerialNumber.SerialNumber
		signer := getSignerInfo(&signer_info)
		for _, cert := range self.Certificates {
			if cert.SerialNumber.Cmp(serial_number) == 0 {
				return signer.Set("Subject", getNamesString(cert.Subject.Names))
			}
		}
		return signer
	}
	return nil
}

func X509ToOrderedDict(cert *x509.Certificate) *ordereddict.Dict {
	result := ordereddict.NewDict().
		Set("SerialNumber", fmt.Sprintf("%x", cert.SerialNumber)).
		Set("SignatureAlgorithm", fmt.Sprintf("%v", cert.SignatureAlgorithm)).
		Set("Subject", getNamesString(cert.Subject.Names)).
		Set("Issuer", getNamesString(cert.Issuer.Names)).
		Set("NotBefore", cert.NotBefore).
		Set("NotAfter", cert.NotAfter).
		Set("PublicKey", printKeyInfo(cert.PublicKeyAlgorithm, cert.PublicKey)).
		Set("Extensions", getExtensions(cert, cert.Extensions))

	return result
}

// Based on github.com/grantae/certinfo
func getExtensions(cert *x509.Certificate, extensions []pkix.Extension) *ordereddict.Dict {
	result := ordereddict.NewDict()
	for _, ext := range extensions {
		getExtensionDict(cert, ext, result)
	}

	return result
}

func getExtensionDict(cert *x509.Certificate, ext pkix.Extension, result *ordereddict.Dict) {
	if len(ext.Id) == 4 && ext.Id[0] == 2 && ext.Id[1] == 5 && ext.Id[2] == 29 {
		switch ext.Id[3] {
		case 14:
			result.Set("SubjectKeyId", ordereddict.NewDict().
				Set("Critical", ext.Critical).
				Set("Value", encodeValue(ext.Value)))

		case 15:
			// keyUsage: RFC 5280, 4.2.1.3
			usages := []string{}
			if cert.KeyUsage&x509.KeyUsageDigitalSignature > 0 {
				usages = append(usages, "Digital Signature")
			}
			if cert.KeyUsage&x509.KeyUsageContentCommitment > 0 {
				usages = append(usages, "Content Commitment")
			}
			if cert.KeyUsage&x509.KeyUsageKeyEncipherment > 0 {
				usages = append(usages, "Key Encipherment")
			}
			if cert.KeyUsage&x509.KeyUsageDataEncipherment > 0 {
				usages = append(usages, "Data Encipherment")
			}
			if cert.KeyUsage&x509.KeyUsageKeyAgreement > 0 {
				usages = append(usages, "Key Agreement")
			}
			if cert.KeyUsage&x509.KeyUsageCertSign > 0 {
				usages = append(usages, "Certificate Sign")
			}
			if cert.KeyUsage&x509.KeyUsageCRLSign > 0 {
				usages = append(usages, "CRL Sign")
			}
			if cert.KeyUsage&x509.KeyUsageEncipherOnly > 0 {
				usages = append(usages, "Encipher Only")
			}
			if cert.KeyUsage&x509.KeyUsageDecipherOnly > 0 {
				usages = append(usages, "Decipher Only")
			}

			result.Set("KeyUsage", ordereddict.NewDict().
				Set("Critical", ext.Critical).
				Set("KeyUsage", usages))

		case 17:
			result.Set("SubjectAlternativeName", ordereddict.NewDict().
				Set("Critical", ext.Critical).
				Set("DNS", cert.DNSNames).
				Set("Email", cert.EmailAddresses).
				Set("IP", cert.IPAddresses))

		case 19:
			result.Set("BasicConstraints", ordereddict.NewDict().
				Set("Critical", ext.Critical).
				Set("IsCA", cert.IsCA).
				Set("MaxPathLen", cert.MaxPathLen))

		case 30:
			// nameConstraints: RFC 5280, 4.2.1.10
			result.Set("NameConstraints", ordereddict.NewDict().
				Set("Critical", ext.Critical).
				Set("Permitted", cert.PermittedDNSDomains))

		case 31:
			// CRLDistributionPoints: RFC 5280, 4.2.1.13
			result.Set("CRLDistributionPoints", ordereddict.NewDict().
				Set("Critical", ext.Critical).
				Set("URI", cert.CRLDistributionPoints))

		case 32:
			// certificatePoliciesExt: RFC 5280, 4.2.1.4
			policies := make([]string, 0, len(cert.PolicyIdentifiers))
			for _, pol := range cert.PolicyIdentifiers {
				policies = append(policies, getPolicyName(pol))
			}

			result.Set("CertificatePolicies", ordereddict.NewDict().
				Set("Critical", ext.Critical).
				Set("Policy", policies))

		case 35:
			// authorityKeyIdentifier: RFC 5280, 4.2.1.1
			result.Set("AuthorityKeyIdentifier", ordereddict.NewDict().
				Set("Critical", ext.Critical).
				Set("KeyId", encodeValue(cert.AuthorityKeyId)))
		case 37:
			// extKeyUsage: RFC 5280, 4.2.1.12
			usage := ordereddict.NewDict().Set("Critical", ext.Critical)
			var list []string
			for _, val := range cert.ExtKeyUsage {
				switch val {
				case x509.ExtKeyUsageAny:
					list = append(list, "Any Usage")
				case x509.ExtKeyUsageServerAuth:
					list = append(list, "TLS Web Server Authentication")
				case x509.ExtKeyUsageClientAuth:
					list = append(list, "TLS Web Client Authentication")
				case x509.ExtKeyUsageCodeSigning:
					list = append(list, "Code Signing")
				case x509.ExtKeyUsageEmailProtection:
					list = append(list, "E-mail Protection")
				case x509.ExtKeyUsageIPSECEndSystem:
					list = append(list, "IPSec End System")
				case x509.ExtKeyUsageIPSECTunnel:
					list = append(list, "IPSec Tunnel")
				case x509.ExtKeyUsageIPSECUser:
					list = append(list, "IPSec User")
				case x509.ExtKeyUsageTimeStamping:
					list = append(list, "Time Stamping")
				case x509.ExtKeyUsageOCSPSigning:
					list = append(list, "OCSP Signing")
				default:
					list = append(list, "UNKNOWN")
				}
			}

			usage.Set("KeyUsage", list)
			result.Set("Extended Key Usage", usage)
		default:
			result.Set(fmt.Sprintf("Unknown extension 2.5.29.%d\n", ext.Id[3]), true)
		}
	}
}

func getNamesString(names []pkix.AttributeTypeAndValue) string {
	var values []string

	for _, name := range names {
		oid := name.Type
		if len(oid) == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 4 {
			switch oid[3] {
			case 3:
				values = append(values, fmt.Sprintf("CN=%s", name.Value))
			case 5:
				values = append(values, fmt.Sprintf("SN=%s", name.Value))
			case 6:
				values = append(values, fmt.Sprintf("C=%s", name.Value))
			case 7:
				values = append(values, fmt.Sprintf("L=%s", name.Value))
			case 8:
				values = append(values, fmt.Sprintf("ST=%s", name.Value))
			case 9:
				values = append(values, fmt.Sprintf("street=%s", name.Value))
			case 10:
				values = append(values, fmt.Sprintf("O=%s", name.Value))
			case 11:
				values = append(values, fmt.Sprintf("OU=%s", name.Value))
			case 17:
				values = append(values, fmt.Sprintf("postalCode=%s", name.Value))

			default:
				values = append(values, fmt.Sprintf("UnknownOID=%s", name.Type.String()))
			}

		} else if oid.Equal(oidEmailAddress) {
			values = append(values, fmt.Sprintf("emailAddress=%s", name.Value))

		} else {

			values = append(values, fmt.Sprintf("UnknownOID=%s", name.Type.String()))
		}
	}
	return strings.Join(values, ", ")
}

func printKeyInfo(pkAlgo x509.PublicKeyAlgorithm, pk interface{}) string {
	buf := &bytes.Buffer{}
	switch pkAlgo {
	case x509.RSA:
		buf.WriteString(fmt.Sprintf("RSA\n"))
		if rsaKey, ok := pk.(*rsa.PublicKey); ok {
			buf.WriteString(fmt.Sprintf("%16sPublic-Key: (%d bit)\n", "", rsaKey.N.BitLen()))
			// Some implementations (notably OpenSSL) prepend 0x00 to the modulus
			// if its most-significant bit is set. There is no need to do that here
			// because the modulus is always unsigned and the extra byte can be
			// confusing given the bit length.
			buf.WriteString(fmt.Sprintf("%16sModulus:", ""))
			for i, val := range rsaKey.N.Bytes() {
				if (i % 15) == 0 {
					buf.WriteString(fmt.Sprintf("\n%20s", ""))
				}
				buf.WriteString(fmt.Sprintf("%02x", val))
				if i != len(rsaKey.N.Bytes())-1 {
					buf.WriteString(":")
				}
			}
			buf.WriteString(fmt.Sprintf("\n%16sExponent: %d (%#x)\n", "", rsaKey.E, rsaKey.E))
		} else {
			return "Expected rsa.PublicKey for type x509.RSA"
		}
	case x509.DSA:
		buf.WriteString(fmt.Sprintf("DSA\n"))
		if dsaKey, ok := pk.(*dsa.PublicKey); ok {
			dsaKeyPrinter("pub", dsaKey.Y, buf)
			dsaKeyPrinter("P", dsaKey.P, buf)
			dsaKeyPrinter("Q", dsaKey.Q, buf)
			dsaKeyPrinter("G", dsaKey.G, buf)
		} else {
			return "Expected dsa.PublicKey for type x509.DSA"
		}
	case x509.ECDSA:
		buf.WriteString(fmt.Sprintf("ECDSA\n"))
		if ecdsaKey, ok := pk.(*ecdsa.PublicKey); ok {
			buf.WriteString(fmt.Sprintf("%16sPublic-Key: (%d bit)\n", "", ecdsaKey.Params().BitSize))
			dsaKeyPrinter("X", ecdsaKey.X, buf)
			dsaKeyPrinter("Y", ecdsaKey.Y, buf)
			buf.WriteString(fmt.Sprintf("%16sCurve: %s\n", "", ecdsaKey.Params().Name))
		} else {
			return "Expected ecdsa.PublicKey for type x509.DSA"
		}
	default:
		return "Unknown public key type"
	}
	return buf.String()
}

// dsaKeyPrinter formats the Y, P, Q, or G components of a DSA public key.
func dsaKeyPrinter(name string, val *big.Int, buf *bytes.Buffer) {
	buf.WriteString(fmt.Sprintf("%16s%s:", "", name))
	for i, b := range val.Bytes() {
		if (i % 15) == 0 {
			buf.WriteString(fmt.Sprintf("\n%20s", ""))
		}
		buf.WriteString(fmt.Sprintf("%02x", b))
		if i != len(val.Bytes())-1 {
			buf.WriteString(":")
		}
	}
	buf.WriteString("\n")
}

func encodeValue(value []byte) string {
	var elements []string
	var data []byte
	if _, err := asn1.Unmarshal(value, &data); err != nil {
		return ""
	}
	for i := 0; i < len(data); i++ {
		elements = append(elements, fmt.Sprintf("%02X", data[i]))
	}
	return strings.Join(elements, ":")
}

func getPolicyName(pol asn1.ObjectIdentifier) string {
	switch {
	case pol.Equal(oidSoftwarePublisher):
		return fmt.Sprintf("Software Publisher (%v)", pol)

	case pol.Equal(oidCodeSigning):
		return fmt.Sprintf("Code Signing (%v)", pol)

	case pol.Equal(oidAnyPolicy):
		return fmt.Sprintf("Any Policy (%v)", pol)

	case pol.Equal(oidTimestampCert):
		return fmt.Sprintf("Timestamping Certificate (%v)", pol)

	default:
		return fmt.Sprintf("%v", pol)
	}
}

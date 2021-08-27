// Parse the resource directory. This code is specifically geared
// towards extracting the Version Information data.

package pe

func (self *IMAGE_NT_HEADERS) ResourceDirectory(
	rva_resolver *RVAResolver) *IMAGE_RESOURCE_DIRECTORY {
	dir := self.DataDirectory(IMAGE_DIRECTORY_ENTRY_RESOURCE)
	offset := rva_resolver.GetFileAddress(dir.VirtualAddress())
	return self.Profile.IMAGE_RESOURCE_DIRECTORY(self.Reader, int64(offset))
}

func (self *IMAGE_RESOURCE_DIRECTORY) Entries() []*IMAGE_RESOURCE_DIRECTORY_ENTRY {
	if self.Offset == 0 {
		return nil
	}

	return ParseArray_IMAGE_RESOURCE_DIRECTORY_ENTRY(self.Profile,
		self.Reader, self.Offset+
			self.Profile.Off_IMAGE_RESOURCE_DIRECTORY__Entries,
		int(CapUint16(self.NumberOfIdEntries()+self.NumberOfNamedEntries(),
			MAX_RESOURCE_DIRECTORY_LENGTH)))
}

func (self *IMAGE_RESOURCE_DIRECTORY_ENTRY) NameString(
	resource_base int64) string {
	if self.NameIsString() > 0 {
		return self.Profile.PrefixedString(
			self.Reader,
			resource_base+int64(self.NameOffset())).String()
	}

	return self.Type().Name
}

func (self *IMAGE_RESOURCE_DIRECTORY_ENTRY) Traverse(
	resource_base int64) []*IMAGE_RESOURCE_DATA_ENTRY {
	result := []*IMAGE_RESOURCE_DATA_ENTRY{}
	self._Traverse(resource_base, &result)

	return result
}

func (self *IMAGE_RESOURCE_DIRECTORY_ENTRY) _Traverse(
	resource_base int64,
	result *[]*IMAGE_RESOURCE_DATA_ENTRY) {

	// Protect us from a deep tree here.
	if self.Offset == 0 || len(*result) > 100 {
		return
	}

	if self.DataIsDirectory() > 0 {
		directory := self.Profile.IMAGE_RESOURCE_DIRECTORY(
			self.Reader, resource_base+int64(self.OffsetToDirectory()))

		for _, entry := range directory.Entries() {
			entry._Traverse(resource_base, result)
		}
	} else {
		data := self.Profile.IMAGE_RESOURCE_DATA_ENTRY(
			self.Reader, resource_base+int64(self.OffsetToData()))
		*result = append(*result, data)
	}
}

func (self *VS_VERSIONINFO) Value() *TagVS_FIXEDFILEINFO {
	// The Value is located after the szKey rounded up to the next
	// word size. The key is always "VS_VERSION_INFO" with length
	// 32.
	return self.Profile.TagVS_FIXEDFILEINFO(
		self.Reader, RoundUpToWordAlignment(
			self.Offset+
				self.Profile.Off_VS_VERSIONINFO_szKey+32))
}

func (self *VS_VERSIONINFO) Children() []*StringFileInfo {
	result := []*StringFileInfo{}

	if self.Offset == 0 {
		return result
	}

	// The children follow the value rounded up to the next word
	// size.
	value := self.Value()
	offset := RoundUpToWordAlignment(value.Offset + int64(value.Size()))
	end := self.Offset + int64(self.Length())

	for offset < end {
		file_info := self.Profile.StringFileInfo(
			self.Reader, offset)

		length := int64(file_info.Length())
		if length == 0 {
			break
		}
		result = append(result, file_info)
		offset += RoundUpToWordAlignment(length)
	}

	return result
}

func (self *StringFileInfo) StringTable() []*StringTable {
	result := []*StringTable{}

	key := self.Key()
	if key == "StringFileInfo" {
		offset := RoundUpToWordAlignment(
			self.Offset + self.Profile.Off_StringFileInfo_Key +
				int64(len(key)+1)*2)
		end := self.Offset + int64(self.Length())

		for offset < end {
			string_table := self.Profile.StringTable(
				self.Reader, offset)
			length := int64(string_table.Length())
			if length == 0 {
				break
			}

			result = append(result, string_table)
			offset += RoundUpToWordAlignment(length)
		}
	}

	return result
}

func (self *StringTable) ResourceStrings() []*ResourceString {
	result := []*ResourceString{}
	key := self.Key()

	offset := RoundUpToWordAlignment(
		self.Offset + self.Profile.Off_StringTable_Key +
			int64(len(key)+1)*2)
	end := self.Offset + int64(self.Length())

	for offset < end {
		resource_string := self.Profile.ResourceString(
			self.Reader, offset)

		length := int64(resource_string.Length())
		if length == 0 {
			break
		}
		result = append(result, resource_string)
		offset += RoundUpToWordAlignment(length)
	}

	return result
}

func (self *ResourceString) Value() string {
	key := self.Key()

	offset := RoundUpToWordAlignment(
		self.Offset + self.Profile.Off_ResourceString_Key +
			int64(len(key)+1)*2)

	return ParseTerminatedUTF16String(self.Reader, offset)
}

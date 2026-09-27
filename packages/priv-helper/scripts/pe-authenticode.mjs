const DOS_SIGNATURE = 0x5a4d;
const PE_SIGNATURE = 0x00004550;
const PE32_MAGIC = 0x10b;
const PE32_PLUS_MAGIC = 0x20b;
const SECURITY_DIRECTORY_INDEX = 4;
const SECTION_HEADER_BYTES = 40;
const WIN_CERTIFICATE_HEADER_BYTES = 8;
const WIN_CERT_REVISION_2_0 = 0x0200;
const WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002;
const CERTIFICATE_ALIGNMENT = 8;
const MIN_FILE_ALIGNMENT = 0x200;
const MAX_FILE_ALIGNMENT = 0x10000;
const PAGE_SIZE = 0x1000;

function fail(message) {
  throw new Error(`invalid PE image: ${message}`);
}

function requireRange(buffer, offset, size, label) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) ||
      offset < 0 || size < 0 || offset > buffer.length - size) {
    fail(`${label} is outside the file`);
  }
}

function addChecked(left, right, label) {
  const result = left + right;
  if (!Number.isSafeInteger(result) || result < left) fail(`${label} overflows`);
  return result;
}

function alignUp(value, alignment, label) {
  const result = Math.ceil(value / alignment) * alignment;
  if (!Number.isSafeInteger(result) || result < value) fail(`${label} overflows`);
  return result;
}

function isPowerOfTwo(value) {
  return Number.isInteger(value) && value > 0 && (value & (value - 1)) === 0;
}

function assertNoOverlaps(ranges, label) {
  const ordered = [...ranges].sort((left, right) => left.start - right.start);
  for (let index = 1; index < ordered.length; index += 1) {
    if (ordered[index].start < ordered[index - 1].end) {
      fail(`${label} overlap`);
    }
  }
}

/**
 * Parse the PE geometry required to remove an Authenticode table without
 * shifting loader-visible bytes. This is deliberately narrower than a Windows
 * loader: it validates headers, section file/virtual layout, the security
 * directory and the absence of opaque overlays—the invariants this build
 * mutates or relies on.
 */
export function inspectPeAuthenticode(input) {
  if (!Buffer.isBuffer(input)) throw new TypeError("PE image must be a Buffer");
  const buffer = input;
  requireRange(buffer, 0, 0x40, "DOS header");
  if (buffer.readUInt16LE(0) !== DOS_SIGNATURE) fail("missing DOS signature");

  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset < 0x40 || peOffset % 4 !== 0) fail("PE header offset is invalid");
  requireRange(buffer, peOffset, 24, "PE and COFF headers");
  if (buffer.readUInt32LE(peOffset) !== PE_SIGNATURE) fail("missing PE signature");

  const coffOffset = peOffset + 4;
  const sectionCount = buffer.readUInt16LE(coffOffset + 2);
  const optionalSize = buffer.readUInt16LE(coffOffset + 16);
  if (sectionCount === 0) fail("image has no sections");

  const optionalOffset = coffOffset + 20;
  requireRange(buffer, optionalOffset, optionalSize, "optional header");
  if (optionalSize < 2) fail("optional header is truncated");
  const magic = buffer.readUInt16LE(optionalOffset);
  const isPe32 = magic === PE32_MAGIC;
  if (!isPe32 && magic !== PE32_PLUS_MAGIC) fail("unsupported optional-header magic");

  const numberOfDirectoriesOffset = optionalOffset + (isPe32 ? 92 : 108);
  const dataDirectoriesOffset = optionalOffset + (isPe32 ? 96 : 112);
  const optionalEnd = optionalOffset + optionalSize;
  if (dataDirectoriesOffset > optionalEnd) fail("optional header is truncated");
  requireRange(buffer, numberOfDirectoriesOffset, 4, "data-directory count");
  const directoryCapacity = Math.floor((optionalEnd - dataDirectoriesOffset) / 8);
  const directoryCount = buffer.readUInt32LE(numberOfDirectoriesOffset);
  if (directoryCount > directoryCapacity) {
    fail("data-directory count exceeds optional-header capacity");
  }
  if (directoryCount <= SECURITY_DIRECTORY_INDEX) {
    fail("optional header has no security data-directory entry");
  }
  const securityDirectoryOffset = dataDirectoriesOffset + SECURITY_DIRECTORY_INDEX * 8;

  const sectionAlignment = buffer.readUInt32LE(optionalOffset + 32);
  const fileAlignment = buffer.readUInt32LE(optionalOffset + 36);
  const sizeOfImage = buffer.readUInt32LE(optionalOffset + 56);
  const sizeOfHeaders = buffer.readUInt32LE(optionalOffset + 60);
  if (!isPowerOfTwo(fileAlignment) || fileAlignment < MIN_FILE_ALIGNMENT ||
      fileAlignment > MAX_FILE_ALIGNMENT) {
    fail("FileAlignment is invalid");
  }
  if (!isPowerOfTwo(sectionAlignment) || sectionAlignment < fileAlignment ||
      (sectionAlignment < PAGE_SIZE && sectionAlignment !== fileAlignment)) {
    fail("SectionAlignment is invalid");
  }
  if (sizeOfHeaders === 0 || sizeOfHeaders % fileAlignment !== 0 ||
      sizeOfHeaders > buffer.length) {
    fail("SizeOfHeaders is invalid");
  }
  if (sizeOfImage === 0 || sizeOfImage % sectionAlignment !== 0) {
    fail("SizeOfImage is invalid");
  }

  const sectionHeadersOffset = optionalEnd;
  const sectionHeadersBytes = sectionCount * SECTION_HEADER_BYTES;
  requireRange(buffer, sectionHeadersOffset, sectionHeadersBytes, "section headers");
  const sectionHeadersEnd = sectionHeadersOffset + sectionHeadersBytes;
  if (sizeOfHeaders < sectionHeadersEnd) fail("SizeOfHeaders does not contain the PE headers");

  const rawRanges = [];
  const virtualRanges = [];
  let sectionDataEnd = sizeOfHeaders;
  const headersVirtualEnd = alignUp(sizeOfHeaders, sectionAlignment, "headers virtual extent");
  let virtualImageEnd = headersVirtualEnd;
  for (let index = 0; index < sectionCount; index += 1) {
    const sectionOffset = sectionHeadersOffset + index * SECTION_HEADER_BYTES;
    const virtualSize = buffer.readUInt32LE(sectionOffset + 8);
    const virtualAddress = buffer.readUInt32LE(sectionOffset + 12);
    const rawSize = buffer.readUInt32LE(sectionOffset + 16);
    const rawOffset = buffer.readUInt32LE(sectionOffset + 20);

    if (virtualAddress === 0 || virtualAddress % sectionAlignment !== 0) {
      fail(`section ${index} virtual address is misaligned`);
    }
    if (virtualAddress < headersVirtualEnd) {
      fail(`section ${index} virtual data overlaps headers`);
    }
    const mappedSize = Math.max(virtualSize, rawSize);
    if (mappedSize > 0) {
      const virtualEnd = addChecked(virtualAddress, mappedSize, `section ${index} virtual data`);
      const alignedVirtualEnd = alignUp(virtualEnd, sectionAlignment, `section ${index} virtual data`);
      if (alignedVirtualEnd > sizeOfImage) fail(`section ${index} exceeds SizeOfImage`);
      virtualRanges.push({ start: virtualAddress, end: alignedVirtualEnd });
      virtualImageEnd = Math.max(virtualImageEnd, alignedVirtualEnd);
    }

    if (rawSize === 0) {
      if (rawOffset !== 0 && rawOffset % fileAlignment !== 0) {
        fail(`section ${index} raw pointer is misaligned`);
      }
      continue;
    }
    if (rawOffset < sizeOfHeaders) fail(`section ${index} raw data overlaps headers`);
    if (rawOffset % fileAlignment !== 0 || rawSize % fileAlignment !== 0) {
      fail(`section ${index} raw data is misaligned`);
    }
    requireRange(buffer, rawOffset, rawSize, `section ${index} raw data`);
    const rawEnd = rawOffset + rawSize;
    rawRanges.push({ start: rawOffset, end: rawEnd });
    sectionDataEnd = Math.max(sectionDataEnd, rawEnd);
  }
  assertNoOverlaps(rawRanges, "section raw-data");
  assertNoOverlaps(virtualRanges, "section virtual-address");
  if (virtualImageEnd !== sizeOfImage) fail("SizeOfImage does not match section layout");

  const certificateOffset = buffer.readUInt32LE(securityDirectoryOffset);
  const certificateSize = buffer.readUInt32LE(securityDirectoryOffset + 4);
  if (certificateOffset === 0 && certificateSize === 0) {
    if (buffer.length !== sectionDataEnd) fail("unsigned image contains an unknown overlay");
    return {
      securityDirectoryOffset,
      certificateOffset: 0,
      certificateSize: 0,
      certificateEnd: 0,
      sectionDataEnd,
    };
  }
  if (certificateOffset === 0 || certificateSize === 0) {
    fail("security directory has a partial certificate-table reference");
  }
  if (certificateOffset % CERTIFICATE_ALIGNMENT !== 0 ||
      certificateSize % CERTIFICATE_ALIGNMENT !== 0) {
    fail("certificate table is not 8-byte aligned");
  }
  if (certificateOffset !== sectionDataEnd) {
    fail("unknown overlay exists between section data and certificate table");
  }
  const certificateEnd = addChecked(certificateOffset, certificateSize, "certificate table");
  requireRange(buffer, certificateOffset, certificateSize, "certificate table");
  if (certificateEnd !== buffer.length) fail("certificate table is not the final file region");

  let cursor = certificateOffset;
  while (cursor < certificateEnd) {
    requireRange(buffer, cursor, WIN_CERTIFICATE_HEADER_BYTES, "WIN_CERTIFICATE header");
    const recordLength = buffer.readUInt32LE(cursor);
    const revision = buffer.readUInt16LE(cursor + 4);
    const certificateType = buffer.readUInt16LE(cursor + 6);
    if (recordLength < WIN_CERTIFICATE_HEADER_BYTES) {
      fail("WIN_CERTIFICATE record is shorter than its header");
    }
    if (revision !== WIN_CERT_REVISION_2_0 ||
        certificateType !== WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
      fail("WIN_CERTIFICATE is not an Authenticode PKCS#7 record");
    }
    const recordEnd = addChecked(cursor, recordLength, "WIN_CERTIFICATE record");
    if (recordEnd > certificateEnd) fail("WIN_CERTIFICATE record exceeds the certificate table");
    const nextRecord = alignUp(recordEnd, CERTIFICATE_ALIGNMENT, "WIN_CERTIFICATE record");
    if (nextRecord > certificateEnd) fail("WIN_CERTIFICATE padding exceeds the certificate table");
    for (let padding = recordEnd; padding < nextRecord; padding += 1) {
      if (buffer[padding] !== 0) fail("WIN_CERTIFICATE padding is not zero");
    }
    cursor = nextRecord;
  }

  return {
    securityDirectoryOffset,
    certificateOffset,
    certificateSize,
    certificateEnd,
    sectionDataEnd,
  };
}

/** Remove a validated EOF Authenticode table from a copied Windows Node PE. */
export function stripPeAuthenticode(input) {
  const info = inspectPeAuthenticode(input);
  if (info.certificateSize === 0) return { image: input, removedBytes: 0 };

  const image = Buffer.from(input.subarray(0, info.certificateOffset));
  image.writeUInt32LE(0, info.securityDirectoryOffset);
  image.writeUInt32LE(0, info.securityDirectoryOffset + 4);
  return { image, removedBytes: info.certificateSize };
}

/** Fail unless a PE is structurally parseable and has no stale certificate. */
export function assertUnsignedPeForSigning(input) {
  const info = inspectPeAuthenticode(input);
  if (info.certificateSize !== 0) {
    throw new Error("PE image still contains an Authenticode certificate table");
  }
}

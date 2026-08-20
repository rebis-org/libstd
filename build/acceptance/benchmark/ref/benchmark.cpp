#include <stdint.h>
#include <string.h>

#include "7zip/Archive/IArchive.h"
#include "7zip/Common/StreamObjects.h"
#include "7zip/IStream.h"
#include "7zip/PropID.h"
#include "Common/MyCom.h"
#include "Common/MyWindows.h"
#include "Common/StringConvert.h"
#include "Windows/PropVariant.h"
#include "ref.h"

extern "C" {
STDAPI CreateObject(const GUID* clsid, const GUID* iid, void** outObject);
}

#define ARC_GUID(id) {0x23170F69, 0x40C1, 0x278A, {0x10, 0x00, 0x00, 0x01, 0x10, (id), 0x00, 0x00}}

class CMemStream : public IInStream, public IOutStream, public CMyUnknownImp {
    // NOLINTBEGIN
    Z7_COM_QI_BEGIN
    Z7_COM_QI_ENTRY_UNKNOWN(ISequentialInStream)
    Z7_COM_QI_ENTRY(ISequentialInStream)
    Z7_COM_QI_ENTRY(IInStream)
    Z7_COM_QI_ENTRY(ISequentialOutStream)
    Z7_COM_QI_ENTRY(IOutStream)
    Z7_COM_QI_END
    Z7_COM_ADDREF_RELEASE
    // NOLINTEND
    const Byte* _data;
    CByteDynBuffer _buf;
    size_t _size;
    UInt64 _pos;
    bool _writable;

  public:
    CMemStream(const Byte* data, size_t size, bool writable)
        : _data(data),
          _size(size),
          _pos(0),
          _writable(writable) {
    }
    size_t GetSize() const {
        return _size;
    }
    const Byte* GetBuffer() const {
        return _writable ? (const Byte*) _buf : _data;
    }
    Z7_COM7F_IMF(Read(void* data, UInt32 size, UInt32* processedSize)) Z7_override {
        if (processedSize != NULL) {
            *processedSize = 0;
        }
        if (size == 0 || _pos >= _size) {
            return S_OK;
        }
        const UInt64 avail = _size - _pos;
        const UInt32 n = (UInt32) (avail < size ? avail : size);
        memcpy(data, GetBuffer() + _pos, n);
        _pos += n;
        if (processedSize != NULL) {
            *processedSize = n;
        }
        return S_OK;
    }
    Z7_COM7F_IMF(Seek(Int64 offset, UInt32 seekOrigin, UInt64* newPosition)) Z7_override {
        Int64 target;
        switch (seekOrigin) {
            case STREAM_SEEK_SET:
                target = offset;
                break;
            case STREAM_SEEK_CUR:
                target = (Int64) _pos + offset;
                break;
            case STREAM_SEEK_END:
                target = (Int64) _size + offset;
                break;
            default:
                return E_INVALIDARG;
        }
        if (target < 0) {
            return MY_E_ERROR_NEGATIVE_SEEK;
        }
        _pos = (UInt64) target;
        if (newPosition != NULL) {
            *newPosition = _pos;
        }
        return S_OK;
    }
    Z7_COM7F_IMF(Write(const void* data, UInt32 size, UInt32* processedSize)) Z7_override {
        if (processedSize != NULL) {
            *processedSize = 0;
        }
        if (size == 0) {
            return S_OK;
        }
        if (!_writable || _pos > _size || !_buf.EnsureCapacity((size_t) _pos + size)) {
            return E_OUTOFMEMORY;
        }
        memcpy((Byte*) _buf + _pos, data, size);
        _pos += size;
        if (_pos > _size) {
            _size = (size_t) _pos;
        }
        if (processedSize != NULL) {
            *processedSize = size;
        }
        return S_OK;
    }
    Z7_COM7F_IMF(SetSize(UInt64 newSize)) Z7_override {
        if (!_writable) {
            return E_NOTIMPL;
        }
        if (newSize > _size && !_buf.EnsureCapacity((size_t) newSize)) {
            return E_OUTOFMEMORY;
        }
        _size = (size_t) newSize;
        return S_OK;
    }
};

template <typename Interface, const GUID& Iid>
class CCallbackBase : public Interface, public CMyUnknownImp {
    // NOLINTBEGIN
    Z7_COM_QI_BEGIN
    Z7_COM_QI_ENTRY_UNKNOWN(IProgress)
    Z7_COM_QI_ENTRY(IProgress)
    else if (iid == Iid) {
        Interface* ti = this;
        *outObject = ti;
    }
    Z7_COM_QI_END
    Z7_COM_ADDREF_RELEASE
    // NOLINTEND

  public:
    Z7_COM7F_IMF(SetTotal(UInt64)) Z7_override {
        return S_OK;
    }
    Z7_COM7F_IMF(SetCompleted(const UInt64*)) Z7_override {
        return S_OK;
    }
};

class CExtractCallback Z7_final : public CCallbackBase<IArchiveExtractCallback, IID_IArchiveExtractCallback> {
    CMemStream* _spec;
    CMyComPtr<ISequentialOutStream> _outStream;
    UInt64 _written = 0;
    bool _ok = false;

  public:
    CExtractCallback()
        : _spec(NULL) {
    }
    UInt64 Written() const {
        return _written;
    }
    bool Ok() const {
        return _ok;
    }
    const Byte* Buffer() const {
        return _spec != NULL ? _spec->GetBuffer() : NULL;
    }
    Z7_COM7F_IMF(GetStream(UInt32, ISequentialOutStream** outStream, Int32 askExtractMode)) Z7_override {
        *outStream = NULL;
        if (askExtractMode != NArchive::NExtract::NAskMode::kExtract) {
            return S_OK;
        }
        // NOLINTNEXTLINE(bugprone-unhandled-exception-at-new)
        _spec = new CMemStream(NULL, 0, true);
        CMyComPtr<ISequentialOutStream> streamPtr(_spec);
        _outStream = streamPtr;
        *outStream = streamPtr.Detach();
        return S_OK;
    }
    Z7_COM7F_IMF(PrepareOperation(Int32)) Z7_override {
        return S_OK;
    }
    Z7_COM7F_IMF(SetOperationResult(Int32 operationResult)) Z7_override {
        _ok = (operationResult == NArchive::NExtract::NOperationResult::kOK);
        if (_ok && _spec != NULL) {
            _written = _spec->GetSize();
        }
        return S_OK;
    }
};

class CUpdateCallback Z7_final : public CCallbackBase<IArchiveUpdateCallback, IID_IArchiveUpdateCallback> {
    const Byte* _data;
    UInt64 _size;
    UString _name;

  public:
    CUpdateCallback(const Byte* data, UInt64 size, const char* name)
        : _data(data),
          _size(size),
          _name(GetUnicodeString(name)) {
    }
    Z7_COM7F_IMF(GetUpdateItemInfo(UInt32, Int32* newData, Int32* newProps, UInt32* indexInArchive)) Z7_override {
        *newData = 1;
        *newProps = 1;
        *indexInArchive = (UInt32) (Int32) -1;
        return S_OK;
    }
    Z7_COM7F_IMF(GetProperty(UInt32, PROPID propID, PROPVARIANT* value)) Z7_override {
        // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.UninitializedObject)
        NWindows::NCOM::CPropVariant prop;
        switch (propID) {
            case kpidPath:
                prop = _name;
                break;
            case kpidIsDir:
                prop = false;
                break;
            case kpidSize:
                prop = _size;
                break;
            default:
                break;
        }
        return prop.Detach(value);
    }
    Z7_COM7F_IMF(GetStream(UInt32, ISequentialInStream** inStream)) Z7_override {
        // NOLINTNEXTLINE(bugprone-unhandled-exception-at-new)
        CMemStream* spec = new CMemStream(_data, (size_t) _size, false);
        CMyComPtr<ISequentialInStream> streamPtr(spec);
        *inStream = streamPtr.Detach();
        return S_OK;
    }
    Z7_COM7F_IMF(SetOperationResult(Int32)) Z7_override {
        return S_OK;
    }
};

template <typename Interface>
static HRESULT CreateHandler(Byte formatId, const GUID& iid, CMyComPtr<Interface>& out) {
    const GUID clsid = ARC_GUID(formatId);
    if (FAILED(CreateObject(&clsid, &iid, (void**) &out)) || !out) {
        return E_FAIL;
    }
    return S_OK;
}

static HRESULT SetStore(IOutArchive* archive) {
    CMyComPtr<ISetProperties> props;
    if (FAILED(archive->QueryInterface(IID_ISetProperties, (void**) &props))) {
        return E_FAIL;
    }
    const wchar_t* const names[] = {L"x"};
    PROPVARIANT value;
    memset(&value, 0, sizeof(value));
    value.vt = VT_UI4;
    value.ulVal = 0;
    return props->SetProperties(names, &value, 1);
}

extern "C" int ref_archive_create(unsigned format_id,
                                  const unsigned char* data,
                                  size_t size,
                                  const char* name,
                                  int store,
                                  unsigned char* out,
                                  size_t cap,
                                  size_t* out_size) {
    *out_size = 0;
    CMyComPtr<IOutArchive> archive;
    if (FAILED(CreateHandler((Byte) format_id, IID_IOutArchive, archive))) {
        return REF_FAIL;
    }
    if (store != 0 && FAILED(SetStore(archive))) {
        return REF_FAIL;
    }
    CMemStream* stream = new CMemStream(NULL, 0, true);
    const CMyComPtr<ISequentialOutStream> outStream(stream);
    const CMyComPtr<IArchiveUpdateCallback> callback(new CUpdateCallback(data, size, name));
    if (FAILED(archive->UpdateItems(outStream, 1, callback))) {
        return REF_FAIL;
    }
    return ref_emit(stream->GetBuffer(), stream->GetSize(), out, cap, out_size);
}

extern "C" int ref_archive_extract(unsigned format_id,
                                   const unsigned char* data,
                                   size_t size,
                                   unsigned char* out,
                                   size_t cap,
                                   size_t* out_size) {
    *out_size = 0;
    CMyComPtr<IInArchive> archive;
    if (FAILED(CreateHandler((Byte) format_id, IID_IInArchive, archive))) {
        return REF_FAIL;
    }
    CMemStream* inStream = new CMemStream(data, size, false);
    const CMyComPtr<IInStream> inStreamPtr(inStream);
    if (archive->Open(inStreamPtr, NULL, NULL) != S_OK) {
        return REF_FAIL;
    }
    CExtractCallback* callback = new CExtractCallback;
    const CMyComPtr<IArchiveExtractCallback> callbackPtr(callback);
    const UInt32 index = 0;
    const HRESULT result = archive->Extract(&index, 1, 0, callbackPtr);
    archive->Close();
    if (result != S_OK || !callback->Ok()) {
        return REF_FAIL;
    }
    return ref_emit(callback->Buffer(), (size_t) callback->Written(), out, cap, out_size);
}

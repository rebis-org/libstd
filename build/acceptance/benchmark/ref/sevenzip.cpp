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
    const Byte* data_;
    CByteDynBuffer buffer_;
    size_t size_;
    UInt64 position_;
    bool writable_;

  public:
    CMemStream(const Byte* data, size_t size, bool writable)
        : data_(data),
          size_(size),
          position_(0),
          writable_(writable) {
    }
    size_t GetSize() const {
        return size_;
    }
    const Byte* GetBuffer() const {
        return writable_ ? (const Byte*) buffer_ : data_;
    }
    Z7_COM7F_IMF(Read(void* data, UInt32 size, UInt32* processedSize)) Z7_override {
        if (processedSize != NULL) {
            *processedSize = 0;
        }
        if (size == 0 || position_ >= size_) {
            return S_OK;
        }
        const UInt64 avail = size_ - position_;
        const UInt32 n = (UInt32) (avail < size ? avail : size);
        memcpy(data, GetBuffer() + position_, n);
        position_ += n;
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
                target = (Int64) position_ + offset;
                break;
            case STREAM_SEEK_END:
                target = (Int64) size_ + offset;
                break;
            default:
                return E_INVALIDARG;
        }
        if (target < 0) {
            return MY_E_ERROR_NEGATIVE_SEEK;
        }
        position_ = (UInt64) target;
        if (newPosition != NULL) {
            *newPosition = position_;
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
        if (!writable_ || position_ > size_ || !buffer_.EnsureCapacity((size_t) position_ + size)) {
            return E_OUTOFMEMORY;
        }
        memcpy((Byte*) buffer_ + position_, data, size);
        position_ += size;
        if (position_ > size_) {
            size_ = (size_t) position_;
        }
        if (processedSize != NULL) {
            *processedSize = size;
        }
        return S_OK;
    }
    Z7_COM7F_IMF(SetSize(UInt64 newSize)) Z7_override {
        if (!writable_) {
            return E_NOTIMPL;
        }
        if (newSize > size_ && !buffer_.EnsureCapacity((size_t) newSize)) {
            return E_OUTOFMEMORY;
        }
        size_ = (size_t) newSize;
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
    CMemStream* spec_;
    CMyComPtr<ISequentialOutStream> out_stream_;
    UInt64 written_ = 0;
    bool ok_ = false;

  public:
    CExtractCallback()
        : spec_(NULL) {
    }
    UInt64 Written() const {
        return written_;
    }
    bool Ok() const {
        return ok_;
    }
    const Byte* Buffer() const {
        return spec_ != NULL ? spec_->GetBuffer() : NULL;
    }
    Z7_COM7F_IMF(GetStream(UInt32, ISequentialOutStream** outStream, Int32 askExtractMode)) Z7_override {
        *outStream = NULL;
        if (askExtractMode != NArchive::NExtract::NAskMode::kExtract) {
            return S_OK;
        }
        // NOLINTNEXTLINE(bugprone-unhandled-exception-at-new)
        spec_ = new CMemStream(NULL, 0, true);
        CMyComPtr<ISequentialOutStream> streamPtr(spec_);
        out_stream_ = streamPtr;
        *outStream = streamPtr.Detach();
        return S_OK;
    }
    Z7_COM7F_IMF(PrepareOperation(Int32)) Z7_override {
        return S_OK;
    }
    Z7_COM7F_IMF(SetOperationResult(Int32 operationResult)) Z7_override {
        ok_ = (operationResult == NArchive::NExtract::NOperationResult::kOK);
        if (ok_ && spec_ != NULL) {
            written_ = spec_->GetSize();
        }
        return S_OK;
    }
};

class CUpdateCallback Z7_final : public CCallbackBase<IArchiveUpdateCallback, IID_IArchiveUpdateCallback> {
    const Byte* data_;
    UInt64 size_;
    UString name_;

  public:
    CUpdateCallback(const Byte* data, UInt64 size, const char* name)
        : data_(data),
          size_(size),
          name_(GetUnicodeString(name)) {
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
                prop = name_;
                break;
            case kpidIsDir:
                prop = false;
                break;
            case kpidSize:
                prop = size_;
                break;
            default:
                break;
        }
        return prop.Detach(value);
    }
    Z7_COM7F_IMF(GetStream(UInt32, ISequentialInStream** inStream)) Z7_override {
        // NOLINTNEXTLINE(bugprone-unhandled-exception-at-new)
        CMemStream* spec = new CMemStream(data_, (size_t) size_, false);
        CMyComPtr<ISequentialInStream> streamPtr(spec);
        *inStream = streamPtr.Detach();
        return S_OK;
    }
    Z7_COM7F_IMF(SetOperationResult(Int32)) Z7_override {
        return S_OK;
    }
};

template <typename Interface>
static HRESULT CreateHandler(Byte formatId, const GUID& iid, CMyComPtr<Interface>& output) {
    const GUID clsid = ARC_GUID(formatId);
    if (FAILED(CreateObject(&clsid, &iid, (void**) &output)) || !output) {
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
                                  unsigned char* output,
                                  size_t capacity,
                                  size_t* output_size) {
    *output_size = 0;
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
    return ref_emit(stream->GetBuffer(), stream->GetSize(), output, capacity, output_size);
}

extern "C" int ref_archive_extract(unsigned format_id,
                                   const unsigned char* data,
                                   size_t size,
                                   unsigned char* output,
                                   size_t capacity,
                                   size_t* output_size) {
    *output_size = 0;
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
    return ref_emit(callback->Buffer(), (size_t) callback->Written(), output, capacity, output_size);
}

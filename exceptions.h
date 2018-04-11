
#ifndef __EXCEPTIONS_H__
#define __EXCEPTIONS_H__

#include <errno.h>
#include <boost/exception/all.hpp>

#ifdef USE_NATIVE_THROW
#define THROW(A) throw A
#define PRINT_EXTRA_ERROR_INFO
#else
#include <boost/exception/diagnostic_information.hpp>
// #include <boost/stacktrace.hpp>
// typedef boost::error_info<struct tag_stacktrace,
// boost::stacktrace::stacktrace> stacktraced;
// #define THROW(A) BOOST_THROW_EXCEPTION(A) <<
// stacktraced(boost::stacktrace::stacktrace())
#define THROW(A) BOOST_THROW_EXCEPTION(A)
#define PRINT_EXTRA_ERROR_INFO \
  std::cerr << boost::current_exception_diagnostic_information()
#endif

typedef boost::error_info<struct tag_msg, std::string> msg_info;

struct OSError : virtual boost::exception, virtual std::exception {};

struct FSError : virtual OSError {};

struct FileIOError : virtual FSError {};

struct FwUpdateError : virtual boost::exception, virtual std::exception {};

struct InvalidMtdDevice : virtual FwUpdateError {};

struct ImageFormatError : virtual FwUpdateError {};

struct BadSignatureError : virtual FwUpdateError {};

struct SignatureMismatch : virtual BadSignatureError {};

typedef enum {
  FW_UPDATE_ERR_NO_ERROR = 0,
  FW_UPDATE_ERR_UNSPECIFIED,
  FW_UPDATE_ERR_INVALID_STATE,
  FW_UPDATE_ERR_OUT_OF_RESOURCES,
  FW_UPDATE_ERR_TRANSFER_INTEGRITY_CHECK_FAILED,
  FW_UPDATE_ERR_TRANSFER_STREAM_ERROR,
  FW_UPDATE_ERR_TRANSFER_INSUFFICIENT_DATA,
  FW_UPDATE_ERR_TRANSFER_UNEXPECTED_DATA,
  FW_UPDATE_ERR_TRANSFER_DECOMPRESS_FAILED,
  FW_UPDATE_ERR_TRANSFER_USB_DEVICE_FAILURE,
  FW_UPDATE_ERR_TRANSFER_FILE_COPY_FAILURE,
  FW_UPDATE_ERR_TRANSFER_UNSPECIFIED,
  FW_UPDATE_ERR_VALIDATE_WRONG_CERTIFICATE,
  FW_UPDATE_ERR_VALIDATE_INVALID_SIGNATURE,
  FW_UPDATE_ERR_VALIDATE_SIGNATURE_MISMATCH,
  FW_UPDATE_ERR_VALIDATE_BAD_CONTENTS,
  FW_UPDATE_ERR_VALIDATE_BAD_VERSION,
  FW_UPDATE_ERR_VALIDATE_UNSPECIFIED,
  FW_UPDATE_ERR_PROGRAM_ERASE_FAILED,
  FW_UPDATE_ERR_PROGRAM_WRITE_FAILED,
  FW_UPDATE_ERR_PROGRAM_VERIFY_FAILED,
  FW_UPDATE_ERR_PROGRAM_UNSPECIFIED,
  FW_UPDATE_ERR_TIMEOUT,
  FW_UPDATE_ERR_MAX = 255,
} fw_error_reasons;

#endif /* __EXCEPTIONS_H__ */

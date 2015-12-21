#pragma once

#include <emmintrin.h>
#include <string>

#if defined(_MSC_VER) && _MSC_VER <= 1800
#define thread_local __declspec(thread)
#elif __APPLE__
#define thread_local __thread
#endif

#if defined(_MSC_VER)
#define never_inline __declspec(noinline)
#else
#define never_inline __attribute__((noinline))
#endif

#if defined(_MSC_VER)
#define safe_buffers __declspec(safebuffers)
#else
#define safe_buffers
#endif

#if defined(_MSC_VER)
#define force_inline __forceinline
#else
#define force_inline __attribute__((always_inline))
#endif

#if defined(_MSC_VER) && _MSC_VER <= 1800
#define alignas(x) _CRT_ALIGN(x)
#endif

#if defined(__GNUG__)

#include <stdlib.h>
#include <cstdint>

#ifndef __APPLE__
#include <malloc.h>
#endif

#define _fpclass(x) std::fpclassify(x)
#define INFINITE 0xFFFFFFFF

#ifdef __APPLE__

// XXX only supports a single timer
#define TIMER_ABSTIME -1
/* The opengroup spec isn't clear on the mapping from REALTIME to CALENDAR
 being appropriate or not.
 http://pubs.opengroup.org/onlinepubs/009695299/basedefs/time.h.html */
#define CLOCK_REALTIME  1 // #define CALENDAR_CLOCK 1 from mach/clock_types.h
#define CLOCK_MONOTONIC 0 // #define SYSTEM_CLOCK 0

typedef int clockid_t;

/* the mach kernel uses struct mach_timespec, so struct timespec
    is loaded from <sys/_types/_timespec.h> for compatability */
// struct timespec { time_t tv_sec; long tv_nsec; };

int clock_gettime(clockid_t clk_id, struct timespec *tp);

#endif /* __APPLE__ */
#endif /* __GNUG__ */

#if defined(_MSC_VER)

// Unsigned 128-bit integer implementation
struct alignas(16) u128
{
	std::uint64_t lo, hi;

	u128() = default;

	u128(const u128&) = default;

	u128(std::uint64_t l)
		: lo(l)
		, hi(0)
	{
	}

	u128 operator +(const u128& r) const
	{
		u128 value;
		_addcarry_u64(_addcarry_u64(0, r.lo, lo, &value.lo), r.hi, hi, &value.hi);
		return value;
	}

	friend u128 operator +(const u128& l, std::uint64_t r)
	{
		u128 value;
		_addcarry_u64(_addcarry_u64(0, r, l.lo, &value.lo), l.hi, 0, &value.hi);
		return value;
	}

	friend u128 operator +(std::uint64_t l, const u128& r)
	{
		u128 value;
		_addcarry_u64(_addcarry_u64(0, r.lo, l, &value.lo), 0, r.hi, &value.hi);
		return value;
	}

	u128 operator -(const u128& r) const
	{
		u128 value;
		_subborrow_u64(_subborrow_u64(0, r.lo, lo, &value.lo), r.hi, hi, &value.hi);
		return value;
	}

	friend u128 operator -(const u128& l, std::uint64_t r)
	{
		u128 value;
		_subborrow_u64(_subborrow_u64(0, r, l.lo, &value.lo), 0, l.hi, &value.hi);
		return value;
	}

	friend u128 operator -(std::uint64_t l, const u128& r)
	{
		u128 value;
		_subborrow_u64(_subborrow_u64(0, r.lo, l, &value.lo), r.hi, 0, &value.hi);
		return value;
	}

	u128 operator +() const
	{
		return *this;
	}

	u128 operator -() const
	{
		u128 value;
		_subborrow_u64(_subborrow_u64(0, lo, 0, &value.lo), hi, 0, &value.hi);
		return value;
	}

	u128& operator ++()
	{
		_addcarry_u64(_addcarry_u64(0, 1, lo, &lo), 0, hi, &hi);
		return *this;
	}

	u128 operator ++(int)
	{
		u128 value = *this;
		_addcarry_u64(_addcarry_u64(0, 1, lo, &lo), 0, hi, &hi);
		return value;
	}

	u128& operator --()
	{
		_subborrow_u64(_subborrow_u64(0, 1, lo, &lo), 0, hi, &hi);
		return *this;
	}

	u128 operator --(int)
	{
		u128 value = *this;
		_subborrow_u64(_subborrow_u64(0, 1, lo, &lo), 0, hi, &hi);
		return value;
	}

	u128 operator ~() const
	{
		u128 value;
		value.lo = ~lo;
		value.hi = ~hi;
		return value;
	}

	u128 operator &(const u128& r) const
	{
		u128 value;
		value.lo = lo & r.lo;
		value.hi = hi & r.hi;
		return value;
	}

	u128 operator |(const u128& r) const
	{
		u128 value;
		value.lo = lo | r.lo;
		value.hi = hi | r.hi;
		return value;
	}

	u128 operator ^(const u128& r) const
	{
		u128 value;
		value.lo = lo ^ r.lo;
		value.hi = hi ^ r.hi;
		return value;
	}

	u128& operator +=(const u128& r)
	{
		_addcarry_u64(_addcarry_u64(0, r.lo, lo, &lo), r.hi, hi, &hi);
		return *this;
	}

	u128& operator +=(uint64_t r)
	{
		_addcarry_u64(_addcarry_u64(0, r, lo, &lo), 0, hi, &hi);
		return *this;
	}

	u128& operator &=(const u128& r)
	{
		lo &= r.lo;
		hi &= r.hi;
		return *this;
	}

	u128& operator |=(const u128& r)
	{
		lo |= r.lo;
		hi |= r.hi;
		return *this;
	}

	u128& operator ^=(const u128& r)
	{
		lo ^= r.lo;
		hi ^= r.hi;
		return *this;
	}
};
#endif

inline std::uint32_t cntlz32(std::uint32_t arg)
{
#if defined(_MSC_VER)
	unsigned long res;
	return _BitScanReverse(&res, arg) ? res ^ 31 : 32;
#else
	return arg ? __builtin_clzll(arg) - 32 : 32;
#endif
}

inline std::uint64_t cntlz64(std::uint64_t arg)
{
#if defined(_MSC_VER)
	unsigned long res;
	return _BitScanReverse64(&res, arg) ? res ^ 63 : 64;
#else
	return arg ? __builtin_clzll(arg) : 64;
#endif
}

// compare 16 packed unsigned bytes (greater than)
inline __m128i sse_cmpgt_epu8(__m128i A, __m128i B)
{
	// (A xor 0x80) > (B xor 0x80)
	const auto sign = _mm_set1_epi32(0x80808080);
	return _mm_cmpgt_epi8(_mm_xor_si128(A, sign), _mm_xor_si128(B, sign));
}

inline __m128i sse_cmpgt_epu16(__m128i A, __m128i B)
{
	const auto sign = _mm_set1_epi32(0x80008000);
	return _mm_cmpgt_epi16(_mm_xor_si128(A, sign), _mm_xor_si128(B, sign));
}

inline __m128i sse_cmpgt_epu32(__m128i A, __m128i B)
{
	const auto sign = _mm_set1_epi32(0x80000000);
	return _mm_cmpgt_epi32(_mm_xor_si128(A, sign), _mm_xor_si128(B, sign));
}

inline __m128 sse_exp2_ps(__m128 A)
{
	const auto x0 = _mm_max_ps(_mm_min_ps(A, _mm_set1_ps(127.4999961f)), _mm_set1_ps(-127.4999961f));
	const auto x1 = _mm_add_ps(x0, _mm_set1_ps(0.5f));
	const auto x2 = _mm_sub_epi32(_mm_cvtps_epi32(x1), _mm_and_si128(_mm_castps_si128(_mm_cmpnlt_ps(_mm_setzero_ps(), x1)), _mm_set1_epi32(1)));
	const auto x3 = _mm_sub_ps(x0, _mm_cvtepi32_ps(x2));
	const auto x4 = _mm_mul_ps(x3, x3);
	const auto x5 = _mm_mul_ps(x3, _mm_add_ps(_mm_mul_ps(_mm_add_ps(_mm_mul_ps(x4, _mm_set1_ps(0.023093347705f)), _mm_set1_ps(20.20206567f)), x4), _mm_set1_ps(1513.906801f)));
	const auto x6 = _mm_mul_ps(x5, _mm_rcp_ps(_mm_sub_ps(_mm_add_ps(_mm_mul_ps(_mm_set1_ps(233.1842117f), x4), _mm_set1_ps(4368.211667f)), x5)));
	return _mm_mul_ps(_mm_add_ps(_mm_add_ps(x6, x6), _mm_set1_ps(1.0f)), _mm_castsi128_ps(_mm_slli_epi32(_mm_add_epi32(x2, _mm_set1_epi32(127)), 23)));
}

inline __m128 sse_log2_ps(__m128 A)
{
	const auto _1 = _mm_set1_ps(1.0f);
	const auto _c = _mm_set1_ps(1.442695040f);
	const auto x0 = _mm_max_ps(A, _mm_castsi128_ps(_mm_set1_epi32(0x00800000)));
	const auto x1 = _mm_or_ps(_mm_and_ps(x0, _mm_castsi128_ps(_mm_set1_epi32(0x807fffff))), _1);
	const auto x2 = _mm_rcp_ps(_mm_add_ps(x1, _1));
	const auto x3 = _mm_mul_ps(_mm_sub_ps(x1, _1), x2);
	const auto x4 = _mm_add_ps(x3, x3);
	const auto x5 = _mm_mul_ps(x4, x4);
	const auto x6 = _mm_add_ps(_mm_mul_ps(_mm_add_ps(_mm_mul_ps(_mm_set1_ps(-0.7895802789f), x5), _mm_set1_ps(16.38666457f)), x5), _mm_set1_ps(-64.1409953f));
	const auto x7 = _mm_rcp_ps(_mm_add_ps(_mm_mul_ps(_mm_add_ps(_mm_mul_ps(_mm_set1_ps(-35.67227983f), x5), _mm_set1_ps(312.0937664f)), x5), _mm_set1_ps(-769.6919436f)));
	const auto x8 = _mm_cvtepi32_ps(_mm_sub_epi32(_mm_srli_epi32(_mm_castps_si128(x0), 23), _mm_set1_epi32(127)));
	return _mm_add_ps(_mm_mul_ps(_mm_mul_ps(_mm_mul_ps(_mm_mul_ps(x5, x6), x7), x4), _c), _mm_add_ps(_mm_mul_ps(x4, _c), x8));
}

#define CHECK_SIZE(type, size) static_assert(sizeof(type) == size, "Invalid " #type " type size")
#define CHECK_ALIGN(type, align) static_assert(alignof(type) == align, "Invalid " #type " type alignment")
#define CHECK_MAX_SIZE(type, size) static_assert(sizeof(type) <= size, #type " type size is too big")
#define CHECK_SIZE_ALIGN(type, size, align) CHECK_SIZE(type, size); CHECK_ALIGN(type, align)
#define CHECK_ASCENDING(constexpr_array) static_assert(::is_ascending(constexpr_array), #constexpr_array " is not sorted in ascending order")

#ifndef _MSC_VER
using u128 = __uint128_t;
#endif

CHECK_SIZE_ALIGN(u128, 16, 16);

#include "types.h"

// bool type replacement for PS3/PSV
class b8
{
	std::uint8_t m_value;

public:
	b8(const bool value)
		: m_value(value)
	{
	}

	operator bool() const //template<typename T, typename = std::enable_if_t<std::is_integral<T>::value>> operator T() const
	{
		return m_value != 0;
	}
};

CHECK_SIZE_ALIGN(b8, 1, 1);

template<typename T, typename = std::enable_if_t<std::is_integral<T>::value>> inline T align(const T& value, u64 align)
{
	return static_cast<T>((value + (align - 1)) & ~(align - 1));
}

// copy null-terminated string from std::string to char array with truncation
template<std::size_t N> inline void strcpy_trunc(char(&dst)[N], const std::string& src)
{
	const std::size_t count = src.size() >= N ? N - 1 : src.size();
	std::memcpy(dst, src.c_str(), count);
	dst[count] = '\0';
}

// copy null-terminated string from char array to char array with truncation
template<std::size_t N, std::size_t N2> inline void strcpy_trunc(char(&dst)[N], const char(&src)[N2])
{
	const std::size_t count = N2 >= N ? N - 1 : N2;
	std::memcpy(dst, src, count);
	dst[count] = '\0';
}

// returns true if all array elements are unique and sorted in ascending order
template<typename T, std::size_t N> constexpr bool is_ascending(const T(&array)[N], std::size_t from = 0)
{
	return from >= N - 1 ? true : array[from] < array[from + 1] ? is_ascending(array, from + 1) : false;
}

// get (first) array element equal to `value` or nullptr if not found
template<typename T, std::size_t N, typename T2> constexpr const T* static_search(const T(&array)[N], const T2& value, std::size_t from = 0)
{
	return from >= N ? nullptr : array[from] == value ? array + from : static_search(array, value, from + 1);
}

// bool wrapper for restricting bool result conversions
struct explicit_bool_t
{
	const bool value;

	constexpr explicit_bool_t(bool value)
		: value(value)
	{
	}

	explicit constexpr operator bool() const
	{
		return value;
	}
};

template<typename T1, typename T2, typename T3 = const char*> struct triplet_t
{
	T1 first;
	T2 second;
	T3 third;

	constexpr bool operator ==(const T1& right) const
	{
		return first == right;
	}
};

// return 32 bit sizeof() to avoid widening/narrowing conversions with size_t
#define sizeof32(type) static_cast<u32>(sizeof(type))

// return 32 bit alignof() to avoid widening/narrowing conversions with size_t
#define alignof32(type) static_cast<u32>(alignof(type))

// return 32 bit .size() for container
template<typename T> inline auto size32(const T& container) -> decltype(static_cast<u32>(container.size()))
{
	const auto size = container.size();
	return size >= 0 && size <= UINT32_MAX ? static_cast<u32>(size) : throw std::length_error(__FUNCTION__);
}

// return 32 bit size for an array
template<typename T, std::size_t Size> constexpr u32 size32(const T(&)[Size])
{
	return Size >= 0 && Size <= UINT32_MAX ? static_cast<u32>(Size) : throw std::length_error(__FUNCTION__);
}


#define WRAP_EXPR(expr) [&]{ return expr; }
#define COPY_EXPR(expr) [=]{ return expr; }
#define PURE_EXPR(expr) [] { return expr; }
#define EXCEPTION(text, ...) fmt::exception(__FILE__, __LINE__, __FUNCTION__, text, ##__VA_ARGS__)
#define VM_CAST(value) vm::impl_cast(value, __FILE__, __LINE__, __FUNCTION__)
#define IS_INTEGRAL(t) (std::is_integral<t>::value || std::is_same<std::decay_t<t>, u128>::value)
#define IS_INTEGER(t) (std::is_integral<t>::value || std::is_enum<t>::value || std::is_same<std::decay_t<t>, u128>::value)
#define IS_BINARY_COMPARABLE(t1, t2) (IS_INTEGER(t1) && IS_INTEGER(t2) && sizeof(t1) == sizeof(t2))
#define CHECK_ASSERTION(expr) if (expr) {} else throw EXCEPTION("Assertion failed: " #expr)
#define CHECK_SUCCESS(expr) if (s32 _r = (expr)) throw EXCEPTION(#expr " failed (0x%x)", _r)

// Some forward declarations for the ID manager
template<typename T> struct id_traits;

#include "StrFmt.h"

std::string v128::to_hex() const
{
	return fmt::format("%016llx%016llx", _u64[1], _u64[0]);
}

std::string v128::to_xyzw() const
{
	return fmt::format("x: %g y: %g z: %g w: %g", _f[3], _f[2], _f[1], _f[0]);
}

std::string fmt::to_hex(u64 value, u64 count)
{
	if (count - 1 >= 16)
	{
		throw EXCEPTION("Invalid count: 0x%llx", count);
	}

	count = std::max<u64>(count, 16 - cntlz64(value) / 4);

	char res[16] = {};

	for (size_t i = count - 1; ~i; i--, value /= 16)
	{
		res[i] = "0123456789abcdef"[value % 16];
	}

	return std::string(res, count);
}

std::string fmt::to_udec(u64 value)
{
	char res[20] = {};
	size_t first = sizeof(res);

	if (!value)
	{
		res[--first] = '0';
	}

	for (; value; value /= 10)
	{
		res[--first] = '0' + (value % 10);
	}

	return std::string(&res[first], sizeof(res) - first);
}

std::string fmt::to_sdec(s64 svalue)
{
	const bool sign = svalue < 0;
	u64 value = sign ? -svalue : svalue;

	char res[20] = {};
	size_t first = sizeof(res);

	if (!value)
	{
		res[--first] = '0';
	}

	for (; value; value /= 10)
	{
		res[--first] = '0' + (value % 10);
	}

	if (sign)
	{
		res[--first] = '-';
	}

	return std::string(&res[first], sizeof(res) - first);
}

//extern const std::string fmt::placeholder = "???";

std::string fmt::replace_first(const std::string& src, const std::string& from, const std::string& to)
{
	auto pos = src.find(from);

	if (pos == std::string::npos)
	{
		return src;
	}

	return (pos ? src.substr(0, pos) + to : to) + std::string(src.c_str() + pos + from.length());
}

std::string fmt::replace_all(const std::string &src, const std::string& from, const std::string& to)
{
	std::string target = src;
	for (auto pos = target.find(from); pos != std::string::npos; pos = target.find(from, pos + 1))
	{
		target = (pos ? target.substr(0, pos) + to : to) + std::string(target.c_str() + pos + from.length());
		pos += to.length();
	}

	return target;
}

//TODO: remove this after every snippet that uses it is gone
//WARNING: not fully compatible with CmpNoCase from wxString
int fmt::CmpNoCase(const std::string& a, const std::string& b)
{
	if (a.length() != b.length())
	{
		return -1;
	}
	else
	{
		return std::equal(a.begin(),
			a.end(),
			b.begin(),
			[](const char& a, const char& b){return ::tolower(a) == ::tolower(b); })
			? 0 : -1;
	}
}

//TODO: remove this after every snippet that uses it is gone
//WARNING: not fully compatible with CmpNoCase from wxString
void fmt::Replace(std::string &str, const std::string &searchterm, const std::string& replaceterm)
{
	size_t cursor = 0;
	do
	{
		cursor = str.find(searchterm, cursor);
		if (cursor != std::string::npos)
		{
			str.replace(cursor, searchterm.size(), replaceterm);
			cursor += replaceterm.size();
		}
		else
		{
			break;
		}
	} while (true);
}

std::vector<std::string> fmt::rSplit(const std::string& source, const std::string& delim)
{
	std::vector<std::string> ret;
	size_t cursor = 0;
	do
	{
		size_t prevcurs = cursor;
		cursor = source.find(delim, cursor);
		if (cursor != std::string::npos)
		{
			ret.push_back(source.substr(prevcurs,cursor-prevcurs));
			cursor += delim.size();
		}
		else
		{
			ret.push_back(source.substr(prevcurs));
			break;
		}
	} while (true);
	return ret;
}

std::vector<std::string> fmt::split(const std::string& source, std::initializer_list<std::string> separators, bool is_skip_empty)
{
	std::vector<std::string> result;

	size_t cursor_begin = 0;

	for (size_t cursor_end = 0; cursor_end < source.length(); ++cursor_end)
	{
		for (auto &separator : separators)
		{
			if (strncmp(source.c_str() + cursor_end, separator.c_str(), separator.length()) == 0)
			{
				std::string candidate = source.substr(cursor_begin, cursor_end - cursor_begin);
				if (!is_skip_empty || !candidate.empty())
					result.push_back(candidate);

				cursor_begin = cursor_end + separator.length();
				cursor_end = cursor_begin - 1;
				break;
			}
		}
	}

	if (cursor_begin != source.length())
	{
		result.push_back(source.substr(cursor_begin));
	}

	return std::move(result);
}

std::string fmt::trim(const std::string& source, const std::string& values)
{
	std::size_t begin = source.find_first_not_of(values);

	if (begin == source.npos)
		return{};

	return source.substr(begin, source.find_last_not_of(values) + 1);
}

std::string fmt::tolower(std::string source)
{
	std::transform(source.begin(), source.end(), source.begin(), ::tolower);

	return source;
}

std::string fmt::toupper(std::string source)
{
	std::transform(source.begin(), source.end(), source.begin(), ::toupper);

	return source;
}

std::string fmt::escape(std::string source)
{
	const std::pair<std::string, std::string> escape_list[] =
	{
		{ "\\", "\\\\" },
		{ "\a", "\\a" },
		{ "\b", "\\b" },
		{ "\f", "\\f" },
		{ "\n", "\\n\n" },
		{ "\r", "\\r" },
		{ "\t", "\\t" },
		{ "\v", "\\v" },
	};

	source = fmt::replace_all(source, escape_list);

	for (char c = 0; c < 32; c++)
	{
		if (c != '\n') source = fmt::replace_all(source, std::string(1, c), fmt::format("\\x%02X", c));
	}

	return source;
}

bool fmt::match(const std::string &source, const std::string &mask)
{
	std::size_t source_position = 0, mask_position = 0;

	for (; source_position < source.size() && mask_position < mask.size(); ++mask_position, ++source_position)
	{
		switch (mask[mask_position])
		{
		case '?': break;

		case '*':
			for (std::size_t test_source_position = source_position; test_source_position < source.size(); ++test_source_position)
			{
				if (match(source.substr(test_source_position), mask.substr(mask_position + 1)))
				{
					return true;
				}
			}
			return false;

		default:
			if (source[source_position] != mask[mask_position])
			{
				return false;
			}

			break;
		}
	}

	if (source_position != source.size())
		return false;

	if (mask_position != mask.size())
		return false;

	return true;
}

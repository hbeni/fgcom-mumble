// Copyright 2020 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef MUMBLEPLUGIN_MUMBLESTRING_H_
#define MUMBLEPLUGIN_MUMBLESTRING_H_

#include "MumbleResourceWrapper.h"

#include <cstring>
#include <ostream>
#include <string>

class MumbleString {
private:
	MumbleResourceWrapper< const char > m_string;
	std::size_t m_size;

public:
	MumbleString(MumbleResourceWrapper< const char > &&string, std::size_t size)
		: m_string(std::move(string)), m_size(size) {}

	std::size_t size() const noexcept { return m_size; }

	const char *c_str() const noexcept { return m_string.get(); }

	bool operator==(const char *other) { return std::strcmp(m_string.get(), other) == 0; }
	bool operator==(const std::string &other) { return other.compare(m_string.get()) == 0; }
	bool operator!=(const char *other) { return std::strcmp(m_string.get(), other) != 0; }
	bool operator!=(const std::string &other) { return other.compare(m_string.get()) != 0; }

	const char &operator[](std::size_t index) const noexcept { return *(m_string.get() + index); }

	friend std::ostream &operator<<(std::ostream &output, const MumbleString &string) {
		for (std::size_t i = 0; i < string.size(); i++) {
			output << string[i];
		}

		return output;
	}

	explicit operator std::string() const noexcept { return std::string(m_string.get(), m_size); }
};

#endif // MUMBLEPLUGIN_MUMBLESTRING_H_

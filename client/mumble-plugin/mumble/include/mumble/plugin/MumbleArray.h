// Copyright 2020 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef MUMBLEPLUGIN_MUMBLEARRAY_H_
#define MUMBLEPLUGIN_MUMBLEARRAY_H_

#include "MumbleResourceWrapper.h"

template< typename ContentType > class MumbleArray {
private:
	MumbleResourceWrapper< ContentType > m_content;
	std::size_t m_size;

public:
	MumbleArray(MumbleResourceWrapper< ContentType > &&content, std::size_t size)
		: m_content(std::move(content)), m_size(size) {}

	std::size_t size() const noexcept { return m_size; };

	ContentType *begin() noexcept { return m_content.get(); }
	ContentType *end() noexcept { return m_content.get() + m_size; }
	const ContentType *begin() const noexcept { return cbegin(); }
	const ContentType *end() const noexcept { return cend(); }
	const ContentType *cbegin() const noexcept { return m_content.get(); }
	const ContentType *cend() const noexcept { return m_content.get() + m_size; }

	ContentType &operator[](std::size_t index) noexcept { return *(m_content.get() + index); }

	const ContentType &operator[](std::size_t index) const noexcept { return *(m_content.get() + index); }
};


#endif // MUMBLEPLUGIN_MUMBLEARRAY_H_

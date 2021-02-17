// Copyright 2020 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef MUMBLEPLUGIN_MUMBLERESOURCEWRAPPER_H_
#define MUMBLEPLUGIN_MUMBLERESOURCEWRAPPER_H_

#include "mumble/plugin/internal/PluginComponents_v_1_0_x.h"

template< typename ResourceType > class MumbleResourceWrapper {
private:
	using freeMemoryFunction = mumble_error_t (*const)(mumble_plugin_id_t, const void *);
	mumble_plugin_id_t m_pluginID;
	freeMemoryFunction m_func;
	ResourceType *m_resource = nullptr;

public:
	// Don't allow copying
	MumbleResourceWrapper(const MumbleResourceWrapper &) = delete;
	MumbleResourceWrapper &operator=(const MumbleResourceWrapper &) = delete;

	explicit MumbleResourceWrapper(ResourceType *resource, mumble_plugin_id_t pluginID, freeMemoryFunction func)
		: m_pluginID(pluginID), m_func(func), m_resource(resource) {}
	~MumbleResourceWrapper() {
		if (m_resource) {
			m_func(m_pluginID, m_resource);
		}
	}

	// Move-semantics
	MumbleResourceWrapper(MumbleResourceWrapper &&other) noexcept
		: m_pluginID(other.m_pluginID), m_func(other.m_func), m_resource(other.m_resource) {
		other.m_resource = nullptr;
	}
	MumbleResourceWrapper &operator=(MumbleResourceWrapper &&rhs) noexcept {
		m_pluginID = rhs.m_pluginID;
		m_func     = rhs.m_func;
		std::swap(m_resource, rhs.m_resource);
	}

	ResourceType *get() noexcept { return m_resource; }
	const ResourceType *get() const noexcept { return m_resource; }

	ResourceType &operator*() noexcept { return *m_resource; }
	const ResourceType &operator*() const noexcept { return *m_resource; }

	// Convert to bool as a pointer does
	operator bool() const noexcept { return m_resource; }
};

#endif // MUMBLEPLUGIN_MUMBLERESOURCEWRAPPER_H_

/**
 * @file encryption_system_registry.h
 * @brief Registration of Built-in Encryption Systems
 */

#ifndef ENCRYPTION_SYSTEM_REGISTRY_H
#define ENCRYPTION_SYSTEM_REGISTRY_H

namespace fgcom {
namespace voice_encryption {

/**
 * @brief Register all built-in encryption systems
 * 
 * This function registers all built-in encryption systems with the factory.
 * It should be called during module initialization.
 */
void registerBuiltInEncryptionSystems();

} // namespace voice_encryption
} // namespace fgcom

#endif // ENCRYPTION_SYSTEM_REGISTRY_H


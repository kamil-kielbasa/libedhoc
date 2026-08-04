/**
 * \file    platform.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC platform services interface.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_PLATFORM_H
#define EDHOC_PLATFORM_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-interface-platform EDHOC platform interface
 * @{
 */

/**
 * \brief EDHOC platform services.
 *
 * Services the library needs from the hosting platform. The application
 * supplies them and binds them with \ref edhoc_bind_platform. Every entry is
 * mandatory, and the binding itself is mandatory: the message-processing API
 * refuses to run until a complete platform is bound.
 */
struct edhoc_platform {
	/**
	 * \brief Securely wipe a memory region (mandatory, non-elidable).
	 *
	 * Erases sensitive data from a buffer once it is no longer needed. The
	 * implementation MUST NOT be eliminated by the compiler even when
	 * \p buffer is never read again (dead-store elimination); e.g.
	 * \c explicit_bzero or C11 \c memset_s.
	 *
	 * \param[out] buffer                Memory region to wipe.
	 * \param length                     Length of \p buffer in bytes.
	 */
	void (*zeroize)(void *buffer, size_t length);
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_PLATFORM_H */

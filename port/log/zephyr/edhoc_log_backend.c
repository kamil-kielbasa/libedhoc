/**
 * \file    edhoc_log_module.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC logging module registration for Zephyr.
 * \version 1.0
 * \date    2026-01-27
 * 
 * \copyright Copyright (c) 2026
 */

/* Include files ----------------------------------------------------------- */
#include <zephyr/logging/log.h>

/* Module defines ---------------------------------------------------------- */

LOG_MODULE_REGISTER(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

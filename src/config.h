/*
 * config.h
 *
 * mercury configuration structures and functions
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "mercury.h"

enum status mercury_config_read_from_file(struct mercury_config *cfg,
                                          const char *filename);

#endif /* CONFIG_H */

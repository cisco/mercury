/*
 * config.h
 *
 * mercury configuration structures and functions
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "mercury.h"
#include "libmerc/libmerc.h"

enum status mercury_config_read_from_file(struct mercury_config &cfg,
                                          struct libmerc_config &global_vars,
                                          const char *filename);

#endif /* CONFIG_H */

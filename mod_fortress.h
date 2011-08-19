/*****************************************************************

  mod_fortress

  Apache Application Intrusion Detection System & Firewall
  Copyright (c) 2002  Ali <io@spunge.org>
  Copyright (c) 2002  Anton Soudovstev <soudovstev@bluewin.ch>
  Copyright (c) 2000  Ali aka "Interstellar" <io@spunge.org>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; version 2.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

  You may copy and distribute this code as long as this copyright
  and disclaimer remains intact.


*****************************************************************/
#ifndef LODH_APACHE_MOD_FORTRESS_H
#define LODH_APACHE_MOD_FORTRESS_H

#include "httpd.h"
#include "http_main.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"
#ifdef STANDARD20_MODULE_STUFF
#include "apr_strings.h"
#include "apr_compat.h"
#include "ap_config.h"
#include "apr_lib.h"
#include "apr_optional.h"
#endif

/* Needed to run the non-transparent proxy */
#define RUN_FORTRESS_IN_THE_MIDDLE

/* Needed to to run the logger */
#define RUN_LOGGER

/* Needed to show mod_fortress/1.0 in the "Server:" header */
#define SHOW_VERSION_COMPONENT



#define BUFFER	1000
#define MODULE_RELEASE   "mod_fortress/1.0"
#define MOD_FORTRESS_MODULE_NAME "mod_fortress"
#define MOD_FORTRESS_VERSION_MAJOR	1
#define MOD_FORTRESS_VERSION_MINOR 0


#ifdef STANDARD20_MODULE_STUFF   /* is it Apache 2.0 ? */
  static void *fortress_create_srv_config( apr_pool_t *p, server_rec *s );
  static void *fortress_create_dir_config( apr_pool_t *p, char *path );
  static const char *fortress_config_cmd_tag( cmd_parms *parms, void *mconfig, const char *arg );
  static const char *fortress_config_logfile( cmd_parms *parms, void *mconfig, const char *arg );
  static const char *fortress_config_log_string( cmd_parms *parms, void *mconfig, const char *arg );
  static void open_log( server_rec *s, apr_pool_t *p );
  static int fortress_log( request_rec *orig );
  static int fortress_fim( request_rec *r );
  static int init_fortress( apr_pool_t *pconf, apr_pool_t *ptemp, apr_pool_t *plog, server_rec *s );

#else                           /* then it's 1.3 */
  static void *fortress_create_srv_config(pool *p, server_rec *s);
  static const char *fortress_config_logfile(cmd_parms *parms, void *mconfig, const char *arg);
  static const char *fortress_config_log_string(cmd_parms *parms, void *mconfig, const char *arg);
  static void *fortress_create_dir_config(pool *p, char *path);
  static int fortress_fim(request_rec *r);
  static const char *fortress_config_cmd_tag(cmd_parms *parms, void *mconfig, const char *arg);
  static const char *fortress_config_cmd_end(cmd_parms *parms, void *mconfig, char *arg);
  static void open_log(server_rec *s, pool *p);
  static void init_fortress(server_rec *s, pool *p);
  static int fortress_log(request_rec *orig);
#endif


static const char* get_args( request_rec *r );
static const char* get_hin( request_rec *r, char *hin );
char *strupper( char *uri );
char *strwdel( char *uri );
void parse_uri( char *uri, char *dst );
void parse_desc( char *uri, char *dst );
void parse_code( char *code, char *dst );
void myitoa( int n, char s[] );
void squeeze( char s[], int c );
void replace( char *str, char *in, int pos );


#endif
// EOF


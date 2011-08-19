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
/****************************************************************

  mod_fortress
  2002 - Merged Apache 1.3/2.0, unix/win32 code in one file  -- Ali <io@spunge.org>
  2002 - Ported to Apache 2.0 on Win32   -- Anton Soudovstev <soudovstev@bluewin.ch>
         Added wildcard signature option -- Anton Soudovstev <soudovstev@bluewin.ch>
         Put signatures in a seperate file -- Anton Soudovstev <soudovstev@bluewin.ch>
  2000 - module original code -- Ali <io@spunge.org>


****************************************************************/

#include "mod_fortress.h"

#ifdef STANDARD20_MODULE_STUFF
  module AP_MODULE_DECLARE_DATA fortress_module;
#else
  module MODULE_VAR_EXPORT fortress_module;
#endif

struct ParseOps{
	char ParsedURI[BUFFER];
	char ParsedCode[BUFFER];
	char ParsedDesc[BUFFER];
};

struct openflags {
	int flags;
	mode_t mode;
};
typedef struct {

#ifdef STANDARD20_MODULE_STUFF
  apr_array_header_t *scripts;
#else
  array_header *scripts;
#endif

} FortressOps;

typedef struct {
#ifdef STANDARD20_MODULE_STUFF
	apr_file_t *log_fd;
#else
	int log_fd;	
#endif
	char *logname;	/* log filename */
	char *format_string;
} LogOps;

#ifdef STANDARD20_MODULE_STUFF
static void *fortress_create_srv_config( apr_pool_t *p, server_rec *s ) {
#else
static void *fortress_create_srv_config(pool *p, server_rec *s) {
#endif

#ifdef STANDARD20_MODULE_STUFF	
	LogOps *cls = (LogOps *) apr_palloc( p, sizeof(LogOps) );
#else
  LogOps *cls = (LogOps *)ap_palloc(p, sizeof(LogOps));
#endif
	cls->logname = "";
	return (void *)cls;
}	

#ifdef STANDARD20_MODULE_STUFF
static void *fortress_create_dir_config( apr_pool_t *p, char *path ) {
#else
static void *fortress_create_dir_config(pool *p, char *path) {
#endif
#ifdef STANDARD20_MODULE_STUFF	
	FortressOps *cfg = (FortressOps *) apr_palloc( p, sizeof(FortressOps) );
	cfg->scripts = apr_array_make( p, 10, sizeof(char *) );
#else
  FortressOps *cfg = (FortressOps *)ap_palloc(p, sizeof(FortressOps));
	cfg->scripts = ap_make_array(p, 10, sizeof(char *));
#endif
  return (void *)cfg;
}

static const char *get_args( request_rec *r ) {
#ifdef STANDARD20_MODULE_STUFF
	return ( r->args != NULL ) ? apr_pstrcat( r->pool, "?", r->args, NULL ): " ";
#else
  return (r->args != NULL) ? ap_pstrcat(r->pool, "?", r->args, NULL): " ";
#endif
}


static const char *get_hin( request_rec *r, char *hin ) {
	
	if( ap_table_get( r->headers_in, hin ) ) {
		return (char *)ap_table_get( r->headers_in, hin );
	}

	return " ";
}


char *strupper( char *uri ) {
#ifdef WIN32
    uri = _strupr(uri);
#else
	char astr[] = "abcdefghijklmnopqrstuvwxyz";
	char bstr[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int i, j;
	for(i = 0; i < (int) strlen(astr); i++) {
		for(j = 0; j < (int) strlen(uri); j++) {
			if(uri[j] == astr[i]) {
        uri[j] = bstr[i];
      }
	  }
	}
#endif
	return uri;	
}


char *strwdel( char *uri ) {
	int i;
	for( i = 0; i < (int) strlen(uri); i++ ) {
		if( uri[i] == '\\' ) {
			uri[i] = '/';
		}
	}

	return uri;
}


//parse request uri from httpd.conf
void parse_uri( char *uri, char *dst ) {
	int i;
	ap_snprintf( dst, 100, "%s", uri );
	for( i = 0; i < (int) strlen(dst); i++ ) {
		if( dst[i] == ';') {
			dst[i] = '\0';
		}
	}
}


//parse request description from httpd.conf
void parse_desc( char *uri, char *dst ) {
	char *p;
	int i;
	
	p = (char *) strchr( uri, ';' );
	if(p == NULL) {
		dst[0] = '\0';
	}

	ap_snprintf(dst, BUFFER, "%s", p + 1);
	
	for(i = 0; i < (int) strlen(dst); i++) {
		if(dst[i] == '[') {
			dst[i] = '\0';
		}
	}
}


//parse the transparent/non-transparent http code if found
void parse_code( char *code, char *dst ) {
	char *start, *end;
	start = (char *)strchr(code, '[');
	if(start == NULL) {
		dst[0] = '\0';
	}
	
	end = (char *) strchr( code, ']' );
	
	if( end == NULL ) {
		dst[0] = '\0';
	}
	
	if( start > end ) {
		dst[0] = '\0';
	}
	
	ap_snprintf( dst, 10, "%s", start + 1 );
	dst[strlen(dst) - 1] = '\0';

}	


void myitoa( int n, char s[] ) {
	
	int i, ii, jj, c, sign;
	
	if( (sign = n) < 0 )
		n =- n;
	i = 0;
	
	do {
		s[i++] = n % 10 + '0';
	} while ( (n /= 10) > 0 );
	
	if( sign < 0 )
		s[i++] = '-';
	s[i] = '\0';
	
	for( ii = 0, jj = strlen(s) - 1; ii < jj; ii++, jj-- ) {
		c = s[ii];
		s[ii] = s[jj];
		s[jj] = c;
	}
}


//squeeze() from  K&R
void squeeze( char s[], int c ) {

	int i, j;

	for( i = j = 0; s[i] !='\0'; i++ ) {
		if( s[i] !=c ) {
			s[j++] = s[i];
		}
	}

	s[j] = '\0';
}


void replace( char *str, char *in, int pos ) {

	char temp[BUFFER];
	char mystring[BUFFER];
	ap_snprintf( mystring, BUFFER, "%s", str );
	mystring[pos] = '\0';
  ap_snprintf( temp, BUFFER, "%s%s%s", mystring, in, &str[pos + 3] );
	ap_snprintf( str, BUFFER, "%s", temp );
}

static const char *fortress_config_cmd_tag( cmd_parms *parms, void *mconfig, const char *arg ) {

	char line[BUFFER];
	FortressOps *cfg = (FortressOps*) mconfig;
	char *fname = NULL;
#ifdef STANDARD20_MODULE_STUFF
	apr_file_t* fd = NULL;
	apr_status_t rv;
	

	if( arg == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 1, parms->server, "mod_fortress: Signatures file is null" );
		exit(1);
	}

	fname = ap_server_root_relative( parms->pool, arg );
	rv = apr_file_open( &fd, fname, APR_READ, APR_OS_DEFAULT, parms->pool );

	if( rv != APR_SUCCESS ) {
		
		ap_log_error(APLOG_MARK, APLOG_ERR, 1, parms->server, "mod_fortress: Can't open signatures file" );
		exit(1);
	}

	
	while( !apr_file_gets( line, sizeof(line), fd ) ) {
					
 		//ignore comments and empty lines
		if( !*line || *line == '#' ) {
			continue;
		}

		*(char **)ap_push_array(cfg->scripts) = apr_pstrdup(parms->pool, line);
	}

#else
  char *sigfile;
  FILE *sf;
  sigfile = ap_server_root_relative(parms->pool, (char *)arg);
  sf = ap_pfopen(parms->pool, sigfile, "r");
  if(sf == NULL) {
    ap_log_error(APLOG_MARK, APLOG_ERR, parms->server, "mod_fortress: Can't open %s", sigfile);
    exit(1);
  }
  while(!feof(sf) && fgets(line, BUFFER, sf)) {
      if (!*line || *line == '#')
          continue;
      *(char **)ap_push_array(cfg->scripts) = ap_pstrdup(parms->pool, line);
	}
#endif
	  return NULL;
}


#ifdef STANDARD20_MODULE_STUFF
static int init_fortress( apr_pool_t *pconf, apr_pool_t *ptemp, apr_pool_t *plog, server_rec *s ) {
#ifdef SHOW_VERSION_COMPONENT
	ap_add_version_component(pconf, apr_psprintf(pconf, "%s/%d.%d",
        MOD_FORTRESS_MODULE_NAME, MOD_FORTRESS_VERSION_MAJOR, MOD_FORTRESS_VERSION_MINOR));
#endif

	for( ;s;s = s->next )
		open_log( s, pconf );

	return OK;
}
#else
static void init_fortress(server_rec *s, pool *p)
{
#ifdef SHOW_VERSION_COMPONENT
	ap_add_version_component(MODULE_RELEASE);
#endif
	for(;s;s = s->next)
		open_log(s, p);
}
#endif

static const char *fortress_config_logfile(cmd_parms *parms, void *mconfig, const char *arg)
{
	LogOps *cls = (LogOps *)ap_get_module_config(parms->server->module_config, &fortress_module);
	(const char *)cls->logname = arg;
	return NULL;
}


static const char *fortress_config_log_string(cmd_parms *parms, void *mconfig, const char *arg)
{
	LogOps *cls = (LogOps *)ap_get_module_config(parms->server->module_config, &fortress_module);
	(const char *)cls->format_string = arg;
	return NULL;
}

#ifdef STANDARD20_MODULE_STUFF
static void open_log( server_rec *s, apr_pool_t *p ) {
	apr_file_t* fd;
	apr_status_t rv;
#else
static void open_log(server_rec *s, pool *p) {
#endif

	LogOps *cls = (LogOps*) ap_get_module_config( s->module_config, &fortress_module );
	struct openflags of;
	char* fname = ap_server_root_relative( p, cls->logname );
	time_t long_time;
	struct tm *tm = NULL;
	time(&long_time);
	tm = localtime(&long_time);

#ifdef STANDARD20_MODULE_STUFF
	of.flags = O_WRONLY|O_APPEND|O_CREAT;
#ifdef WIN32
	of.mode = _S_IREAD | _S_IWRITE;
#else	
	of.mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
#endif
	
	//append to the log file the current date&time
	strcat(fname, ".");
	strcat(fname, (char *) ap_psprintf(p, "%04d%02d%02d%02d%02d%02d", 1900+tm->tm_year,
			                                                tm->tm_mon+1,
			                                                tm->tm_mday,
			                                                tm->tm_hour,
			                                                tm->tm_min,
			                                                tm->tm_sec ));
	if( !fname ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 1, s, "mod_fortress: Can't open %s", fname);
		exit(1);
	}

	rv = apr_file_open( &fd, fname, APR_WRITE|APR_APPEND|APR_CREATE, APR_OS_DEFAULT, p );
  	if( rv != APR_SUCCESS ) {
		ap_log_error( APLOG_MARK, APLOG_ERR, rv, s, "mod_fortress: could not open file %s", fname);
    exit(1);
  }

	apr_file_inherit_set(fd);
	cls->log_fd = fd;
#else
	
	of.flags = O_WRONLY|O_APPEND|O_CREAT;
#ifdef WIN32
	of.mode = _S_IREAD | _S_IWRITE;
#else
	of.mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
#endif
	strcat(fname, ".");
	strcat(fname, (char *) ap_psprintf(p, "%04d%02d%02d%02d%02d%02d", 1900+tm->tm_year,
		                                          tm->tm_mon+1,							                                                                        tm->tm_mday,					                                                                        tm->tm_hour,					                                                                        tm->tm_min,						                                                                        tm->tm_sec ));
		
	if(fname != '\0') {
	cls->log_fd = ap_popenf(p, fname, of.flags, of.mode);
	}
	if(cls->log_fd < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, s, "mod_fortress: Can't open %s", fname);
		exit(1);
	}
#endif
}


static int fortress_fim( request_rec *r ) {
	
	FortressOps *cfg = (FortressOps *) ap_get_module_config( r->per_dir_config, &fortress_module );
	struct ParseOps pops;
	char **scrs = (char **) cfg->scripts->elts;

  	int i;
	char* wildcard = NULL;
	int wildcarded = 0;
	
	
	for( i = 0; i < cfg->scripts->nelts; i++ ) {
	
		parse_uri(scrs[i], pops.ParsedURI);
		parse_code(scrs[i], pops.ParsedCode);
		squeeze(pops.ParsedURI, ' ');

		if( ( wildcard = strchr( pops.ParsedURI, '*' ) ) != NULL ) {

			pops.ParsedURI[ wildcard-pops.ParsedURI ] = '\0';
			
			if(strstr(strwdel(r->uri), pops.ParsedURI) || 
			   strstr(strwdel(r->uri), strupper(pops.ParsedURI))) {
				wildcarded = 1;
			}
		}

		  if(!strcmp(pops.ParsedURI, strwdel(r->uri)) || 
		     !strcasecmp(pops.ParsedURI, r->uri) || 
		     wildcarded)  {
			wildcarded = 0;
			if( atoi( pops.ParsedCode ) == 0 || pops.ParsedCode == NULL ) {
				return OK;
			} else {
				return atoi( pops.ParsedCode );
			}
		}
	}
	
	return OK;
}


static int fortress_log( request_rec *orig ) {
	
	LogOps *cls = (LogOps*) ap_get_module_config( orig->server->module_config, &fortress_module );
	FortressOps *cfg = (FortressOps *) ap_get_module_config( orig->per_dir_config, &fortress_module );
	struct ParseOps pops;
	
	//struct tm *tm = localtime( (time_t*) &orig->request_time );

	time_t long_time;
  	struct tm *tm = NULL;

	char** scr = (char **) cfg->scripts->elts;
	request_rec *r;
	char fs[BUFFER];
	char buf[BUFFER], temp[BUFFER], temp2[BUFFER];
	int x, len;
	int i, j;
	char* wildcard = NULL;
	int wildcarded = 0;
		
	time( &long_time );
	tm = localtime( &long_time );

	for( r = orig ;r->next; r = r-> next )
		continue;	

	for( i = 0; i < cfg->scripts->nelts; i++ ) {
				
		parse_uri( scr[i], pops.ParsedURI );	
		parse_desc( scr[i], pops.ParsedDesc );
		squeeze( pops.ParsedURI, ' ' );
		if((wildcard = strchr(pops.ParsedURI, '*')) != NULL ) {
			
			pops.ParsedURI[wildcard-pops.ParsedURI] = '\0';

			if(strstr(strwdel(orig->uri), pops.ParsedURI) || 
			   strstr(strwdel(orig->uri), strupper(pops.ParsedURI))) {
				char wc[BUFFER];
				ap_snprintf( wc, BUFFER, "[*] Wildcarded entry follows, signature : %s\n", scr[i] );
				len = strlen(wc);
#ifdef STANDARD20_MODULE_STUFF
		apr_file_write(cls->log_fd, wc, &len );
#else
		write(cls->log_fd, wc, strlen(wc));
#endif
				wildcarded = 1;
			}

		}
		
			if(!strcmp(pops.ParsedURI, strwdel(orig->uri)) ||
			   !strcasecmp(pops.ParsedURI, orig->uri) || wildcarded) {
			
			//pull down the wildcard
			wildcarded = 0;

 			//parse the format string
			ap_snprintf( fs, BUFFER, "%s", cls->format_string );
			for( j = 0; j < (int) strlen(fs); j++ ) {
				if( fs[j] == '%' && fs[j+1] == 'R' )  { //request based
					if( fs[j+2] == 'u' ) {
						replace( fs, orig->uri, j );
					}
				
					if( fs[j+2] == 'r' ) {
						replace( fs, orig->the_request, j );
					}
	
					if( fs[j+2] == 'd' ) {
						replace( fs, pops.ParsedDesc, j );
					}
			
					if( fs[j+2] == 'm' ) {
						replace( fs, (char *) orig->method, j );
					}
					
					if( fs[j+2] == 'p' ) {
						replace( fs, orig->protocol, j );
					}
					
					if( fs[j+2] == 'q' ) {
						replace( fs, (char *) get_args( orig ), j );
					}
				} //! request based

				if( fs[j] == '%' && fs[j+1] == 'C' ) { //connection based
					if( fs[j+2] == 'i' ) {
						replace( fs, orig->connection->remote_ip, j );
					}
					
					if( fs[j+2] == 'h' ) {
#ifdef STANDARD20_MODULE_STUFF
		replace( fs, (char *) ap_get_remote_host( orig->connection, orig->per_dir_config, REMOTE_NAME, NULL ), j );
#else		
		replace(fs, (char *)ap_get_remote_host(orig->connection, orig->per_dir_config, REMOTE_NAME), j);
#endif					
					}
					
					if( fs[j+2] == 'l' ) {
						replace( fs, orig->connection->local_ip, j );
					}
				}  //!connection based

				if( fs[j] == '%' && fs[j+1] == 'S' ) { //server based
					if( fs[j+2] == 'n' ) {
						replace( fs, (char *)ap_get_server_name(orig), j) ;
					}
					
					if( fs[j+2] == 'h' ) {
						replace( fs, orig->server->server_hostname, j );
					}
		
					if( fs[j+2] == 'p' ) {
						replace( fs, (char *)ap_psprintf(r->pool, "%u", r->server->port), j ); 	
					}
			
					if( fs[j+2] == 'v' ) {
						replace( fs, orig->server->addrs->virthost, j );
					}
			
					if( fs[j+2] == 'a' ) {
						replace( fs, orig->server->server_admin, j );
					}
		
				} //!server based
	
				if( fs[j] == '%' && fs[j+1] == 'T' ) {  //time based
		
					if( fs[j+2] == 's' ) {
						replace( fs, (char *) ap_psprintf( r->pool, "%02d", tm->tm_sec ), j );
					}
					
					if( fs[j+2] == 'm' ) {
						replace( fs, (char *) ap_psprintf( r->pool, "%02d", tm->tm_min ), j );
					}
		
					if( fs[j+2] == 'h' ) {
						replace( fs, (char *) ap_psprintf(r->pool, "%02d", tm->tm_hour ), j );
					}
					
					if( fs[j+2] == 'd' ) {
						replace( fs, (char *) ap_psprintf( r->pool, "%02d", tm->tm_mday ), j );
					}
				
					if( fs[j+2] == 'M' ) {
						replace( fs, (char *) ap_psprintf( r->pool, "%02d", tm->tm_mon+1 ), j );
					}
			
					if( fs[j+2] == 'y' ) {
						replace( fs, (char *) ap_psprintf( r->pool, "%2d", tm->tm_year+1900 ), j );
					}
		
				}	
	
				if( fs[j] == '%' && fs[j+1] == 'H' ) {
					ap_snprintf( temp, BUFFER, "%s", &fs[j+3] );
					
					for( i = 0; i < (int) strlen(fs); i++ ) {
						if( temp[i] == ']' ) {
							temp[i] = '\0';
							x = i;
						}
					}

					ap_snprintf( temp2, BUFFER, "%s", fs );
					temp2[j] = '\0';
					ap_snprintf( buf, BUFFER, "%s%s%s", temp2, (char *)get_hin(orig, temp), &temp2[j + 4 + strlen(temp)] );
					ap_snprintf( fs, BUFFER, "%s", buf );
		
				}


			}

			for( i = 0; i < (int) strlen(fs); i++ ) {
				if( fs[i] == '&' ) {
					fs[i] = '\n';
				}
			}
			
			strcat( fs, "\n" );
			len = strlen( fs );
#ifdef STANDARD20_MODULE_STUFF
			apr_file_write( cls->log_fd, fs, &len );
			return OK;
#else
    write(cls->log_fd, fs, strlen(fs));
			return OK;
#endif

		}
	}

	return OK;
}

#ifdef STANDARD20_MODULE_STUFF
static const command_rec fortress_cmds[] = {
    AP_INIT_TAKE1(
							"FortressSignatures",
							fortress_config_cmd_tag,
							NULL,
							OR_ALL,
							"list of signatures" ),
    AP_INIT_TAKE1(
							"FortressLog",
							fortress_config_logfile,
							NULL,
							RSRC_CONF,
							"name of logfile" ),
    AP_INIT_TAKE1(
							"FortressLogString",
							fortress_config_log_string,
							NULL,
							RSRC_CONF,
							"format string" ),
    {NULL}
};


static void register_hooks( apr_pool_t *p ) {
	
	ap_hook_post_config( init_fortress, NULL, NULL, APR_HOOK_FIRST );
	ap_hook_log_transaction( fortress_log, NULL, NULL, APR_HOOK_MIDDLE );
	#ifdef RUN_FORTRESS_IN_THE_MIDDLE
		ap_hook_header_parser( fortress_fim, NULL, NULL, APR_HOOK_MIDDLE );
	#endif
}


module AP_MODULE_DECLARE_DATA fortress_module = {
	STANDARD20_MODULE_STUFF,
	fortress_create_dir_config,	 // create per-dir config structures
	NULL,  //dir merger
	fortress_create_srv_config,	 // create per-server config structures
	NULL,  //merge server config
	fortress_cmds,	 //  table of config file commands
	register_hooks //hooks
};


#else
static command_rec fortress_cmds[] = {
    {"FortressSignatures", fortress_config_cmd_tag, NULL, OR_ALL, TAKE1, "list of signatures"},
    {"FortressLog", fortress_config_logfile, NULL, RSRC_CONF, TAKE1, "name of logfile"},
    {"FortressLogString", fortress_config_log_string, NULL, RSRC_CONF, TAKE1, "format string"},
    {NULL},
};

module MODULE_VAR_EXPORT fortress_module = {
    STANDARD_MODULE_STUFF,
    init_fortress,				  // module initializer
    fortress_create_dir_config,	 // create per-dir config structures
    NULL,
    fortress_create_srv_config,	 // create per-server config structures
    NULL,
    fortress_cmds,	 //  table of config file commands
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
#ifdef RUN_LOGGER
    fortress_log,				// log a transaction
#else
    NULL,
#endif /* !RUN_LOGGER */
#ifdef RUN_FORTRESS_IN_THE_MIDDLE
    fortress_fim,				// header parser
#else
    NULL,
#endif /* !RUN_FORTRESS_IN_THE_MIDDLE */
    NULL,
    NULL,
    NULL
};



#endif




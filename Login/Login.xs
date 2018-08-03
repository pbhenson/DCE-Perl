#include "../DCE_Perl.h"

#include <dce/sec_login.h>

#ifdef I_PWD
#include <pwd.h>
#endif

/* $Id: Login.xs,v 1.11 1996/11/01 19:24:57 dougm Exp $ */ 

typedef struct login_obj {
  sec_login_handle_t	context;
} login_obj;

typedef login_obj *DCE__Login__obj;


MODULE = DCE::Login		PACKAGE = DCE::Login		PREFIX = sec_login_

# this will get a sealed certificate for the principal from the secserver,
# and return a list of ($login_context, $status)

void
sec_login_setup_identity(package = "DCE::Login", principal, flags=sec_login_no_flags)
  char *package
  unsigned_char_p_t	principal
  sec_login_flags_t	flags

  PPCODE:
  {
    DCE__Login__obj	login;
    error_status_t	status;
    SV *sv;

    sv = &PL_sv_undef;

    if (!(login = (DCE__Login__obj)malloc(sizeof(login_obj))))
      status = sec_login_s_no_memory;
    else {
      sec_login_setup_identity(principal, flags, &login->context, &status);
      if (status)
	free(login);
      else {
	sv = sv_newmortal();
	sv_setref_pv(sv,"DCE::Login::obj",(void*)login);
      }
    }
    
    XPUSHs(sv);
    DCESTATUS;
  }

void
sec_login_get_current_context(package = "DCE::Login")
  char *package

  PPCODE:
  {
    DCE__Login__obj	login;
    error_status_t	status;
    SV *sv;

    sv = &PL_sv_undef;

    if (!(login = (DCE__Login__obj)malloc(sizeof(login_obj))))
      status = sec_login_s_no_memory;
    else {
      sec_login_get_current_context(&login->context, &status);
      if (status)
	free(login);
      else {
	sv = sv_newmortal();
	sv_setref_pv(sv,"DCE::Login::obj",(void*)login);
      }
    }

   XPUSHs(sv); \
   DCESTATUS

  }


void
sec_login_import_context(package = "DCE::Login", buf_len, buf)
  char *package;
  unsigned32	buf_len
  char *	buf

  PPCODE:
  {
    DCE__Login__obj login;
    error_status_t	status;
    SV *sv;

    sv = &PL_sv_undef;

    if (!(login = (DCE__Login__obj)malloc(sizeof(login_obj))))
      status = sec_login_s_no_memory;
    else {
      sec_login_import_context(buf_len, buf, &login->context, &status);
      
      if (status)
	free(login);
      else {
	sv = sv_newmortal();
	sv_setref_pv(sv,"DCE::Login::obj",(void*)login);
      }
    }
    
    XPUSHs(sv);
    DCESTATUS;
  }

MODULE = DCE::Login		PACKAGE = DCE::Login::obj		PREFIX = sec_login_

void
sec_login_validate_identity(login, password)
  DCE::Login::obj	login
  char *	password  

  PPCODE:
  {
    boolean32	reset_passwd, retval;
    sec_login_auth_src_t	auth_src;
    error_status_t	status;
    sec_passwd_rec_t	passwd;
    
    /* load passwd struct */
    passwd.key.key_type = sec_passwd_plain;
    passwd.key.tagged_union.plain = password;
    passwd.pepper = NULL;
    passwd.version_number = sec_passwd_c_version_none;
                        
    retval = sec_login_validate_identity(login->context, &passwd, 
					 &reset_passwd, &auth_src, &status);
    if(GIMME == G_ARRAY) {
	EXTEND(sp,3);
	PUSHs_iv(retval);
	PUSHs_iv(reset_passwd);
	PUSHs_iv(auth_src);
    }
    DCESTATUS;
  }    

void
sec_login_certify_identity(login)
  DCE::Login::obj	login

  PPCODE:
  {
    error_status_t	status;
    boolean32 retval;
    retval = sec_login_certify_identity(login->context, &status);
    if(GIMME == G_ARRAY)
	XPUSHs_iv(retval);
    DCESTATUS;
  }

void
sec_login_valid_and_cert_ident(login, password)
  DCE::Login::obj	login
  char *password  

  PPCODE:
  {
    boolean32	reset_passwd, retval;
    sec_login_auth_src_t	auth_src;
    error_status_t	status;
    sec_passwd_rec_t	passwd;
    sec_passwd_str_t    pbuf;

    strncpy((char *)pbuf, password, sec_passwd_str_max_len);
    pbuf[sec_passwd_str_max_len] = '\0';

    /* load passwd struct */
    passwd.key.key_type = sec_passwd_plain;
    passwd.key.tagged_union.plain = (unsigned char *)pbuf;
    passwd.pepper = NULL;
    passwd.version_number = sec_passwd_c_version_none;
            
    retval = sec_login_valid_and_cert_ident(login->context, &passwd, &reset_passwd, &auth_src, &status);
    if(GIMME == G_ARRAY) {
	EXTEND(sp,3);
	PUSHs_iv(retval);
	PUSHs_iv(reset_passwd);
	PUSHs_iv(auth_src);
    }
    DCESTATUS;
  }    

void
sec_login_valid_from_keytable(login, keyfile = "")
  DCE::Login::obj	login
  char *keyfile

    CODE:
    {
    unsigned32          kvno, asvc = rpc_c_authn_dce_secret;
    boolean32	reset_passwd;
    sec_login_auth_src_t	auth_src;
    error_status_t	status;

    sec_login_valid_from_keytable(login->context, asvc, keyfile, 0, &kvno,
				  &reset_passwd, &auth_src, &status);
    EXTEND(sp,2);
    PUSHs_iv(reset_passwd);
    PUSHs_iv(auth_src);
    DCESTATUS;
  }

void
sec_login_set_context(login)
  DCE::Login::obj	login

  PPCODE:
  {
    error_status_t	status;
    sec_login_set_context(login->context, &status);
    DCESTATUS;
  }

void
sec_login_purge_context(login)
  DCE::Login::obj	login

  PPCODE:
  {
    error_status_t	status;
    sec_login_purge_context(&(login->context), &status);
    DCESTATUS;
  }

void
sec_login_release_context(login)
  DCE::Login::obj	login

  PPCODE:
  {
    error_status_t	status;
    sec_login_release_context(&login->context, &status);
    DCESTATUS;
  }

void
sec_login_DESTROY(login)
  DCE::Login::obj	login

  PPCODE:
  {
    if (login) {
      if (login->context) {
	error_status_t	status;
	sec_login_release_context(&login->context, &status);
      }
      free(login);
    }
  }

void
sec_login_get_expiration(login)
  DCE::Login::obj	login

  PPCODE:
  {
    signed32	identity_expiration;
    error_status_t	status;
    sec_login_get_expiration(login->context, &identity_expiration, &status);
    XPUSHs_iv(identity_expiration);
    DCESTATUS;
  }

void
sec_login_refresh_identity(login)
  DCE::Login::obj	login

  PPCODE:
  {
    error_status_t	status;
    sec_login_refresh_identity(login->context, &status);
    DCESTATUS;
  }

void
sec_login_export_context(login, buf_len)
  DCE::Login::obj	login
  unsigned32	buf_len

  PPCODE:
  {
    char *	buf;
    unsigned32	len_used;
    unsigned32	len_needed;
    error_status_t	status;
  
    buf = malloc(buf_len);
    sec_login_export_context(login->context, buf_len, buf, &len_used, &len_needed, &status);

    EXTEND(sp, 3);
    PUSHs_pv(buf); 
    PUSHs_iv(len_used);
    PUSHs_iv(len_needed);
    DCESTATUS;
    free(buf);
  }

void
sec_login_get_pwent(login)
  DCE::Login::obj 	login

  PPCODE:
  {
    struct passwd *pwd;
    error_status_t 	status;
    HV *hv;

    sec_login_get_pwent(login->context, (sec_login_passwd_t *)&pwd, &status);

    iniHV;
    hv_store(hv, "name", 4, newSVpv(pwd->pw_name,0),0);
    hv_store(hv, "passwd", 6, newSVpv(pwd->pw_passwd,0),0);
    hv_store(hv, "gecos", 5, newSVpv(pwd->pw_gecos,0),0);    
    hv_store(hv, "dir", 3, newSVpv(pwd->pw_dir,0),0);
    hv_store(hv, "shell", 5, newSVpv(pwd->pw_shell,0),0);
    hv_store(hv, "uid", 3, newSViv(pwd->pw_uid),0);
    hv_store(hv, "gid", 3, newSViv(pwd->pw_gid),0);
    /*
#ifdef something...
    hv_store(hv, "class", 5, newSVpv(pwd->pw_class,0),0);
    hv_store(hv, "change", 6, newSViv(pwd->pw_change),0);
    hv_store(hv, "expire", 6, newSViv(pwd->pw_expire),0);
#endif
    */

    XPUSHs(newRV((SV*)hv)); 
    DCESTATUS;
  }



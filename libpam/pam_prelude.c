/*
 * pam_prelude.c -- prelude reporting
 * http://www.prelude-ids.org
 *
 * (C) Sebastien Tricaud 2005 <toady@gscore.org>
 */

#include <stdio.h>
#include <syslog.h>

#ifdef PRELUDE

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-message-print.h>

#include "pam_prelude.h"
#include "pam_private.h"


#define ANALYZER_CLASS "pam"
#define ANALYZER_MODEL "PAM"
#define ANALYZER_MANUFACTURER "Sebastien Tricaud, http://www.kernel.org/pub/linux/libs/pam/"

#define DEFAULT_ANALYZER_NAME "PAM"
#define DEFAULT_ANALYZER_CONFIG LIBPRELUDE_CONFIG_PREFIX "/etc/prelude/default/idmef-client.conf"

#define PAM_VERSION LIBPAM_VERSION_STRING

static const char *pam_get_item_service(pam_handle_t *pamh);
static const char *pam_get_item_user(pam_handle_t *pamh);
static const char *pam_get_item_user_prompt(pam_handle_t *pamh);
static const char *pam_get_item_tty(pam_handle_t *pamh);
static const char *pam_get_item_ruser(pam_handle_t *pamh);
static const char *pam_get_item_rhost(pam_handle_t *pamh);

static int setup_analyzer(idmef_analyzer_t *analyzer);
static void pam_alert_prelude(const char *msg, void *data, pam_handle_t *pamh, int authval);
static int pam_alert_prelude_init(pam_handle_t *pamh, int authval);
static int generate_additional_data(idmef_alert_t *alert, const char *meaning, const char *data);


/*******************
 * some syslogging *
 *******************/
static void 
_pam_log(int err, const char *format, ...)
{
    va_list args;
    va_start(args, format);

#ifdef MAIN
    vfprintf(stderr,format,args);
    fprintf(stderr,"\n");
#else
    openlog("libpam", LOG_CONS|LOG_PID, LOG_AUTH);
    vsyslog(err, format, args);
    closelog();
#endif
    va_end(args);
}

static const char *
pam_get_item_service(pam_handle_t *pamh)
{
        const char *service = NULL;

	pam_get_item(pamh, PAM_SERVICE, (const void **)&service);

        return (const char *)service;
}

static const char *
pam_get_item_user(pam_handle_t *pamh)
{
        const char *user = NULL;

	pam_get_item(pamh, PAM_USER, (const void **)&user);

        return (const char *)user;
}

static const char *
pam_get_item_user_prompt(pam_handle_t *pamh)
{
        const char *user_prompt = NULL;

	pam_get_item(pamh, PAM_USER_PROMPT, (const void **)&user_prompt);

        return (const char *)user_prompt;
}

static const char *
pam_get_item_tty(pam_handle_t *pamh)
{
        const char *tty = NULL;

	pam_get_item(pamh, PAM_TTY, (const void **)&tty);

        return (const char *)tty;
}

static const char *
pam_get_item_ruser(pam_handle_t *pamh)
{
        const char *ruser = NULL;

	pam_get_item(pamh, PAM_RUSER, (const void **)&ruser);

        return (const char *)ruser;
}

static const char *
pam_get_item_rhost(pam_handle_t *pamh)
{
        const char *rhost = NULL;

	pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);

        return (const char *)rhost;
}

/***************************************************************** 
 * Returns a string concerning the authentication value provided *
 *****************************************************************/
static const char *
pam_get_alert_description(int authval)
{
        const char *retstring = NULL;

        switch(authval) {
        case PAM_SUCCESS:
                retstring = "Authentication success";
                break;
        case PAM_OPEN_ERR:
                retstring = "dlopen() failure when dynamically loading a service module";
                break;
        case PAM_SYMBOL_ERR:
                retstring = "Symbol not found";
                break;
        case PAM_SERVICE_ERR:
                retstring = "Error in service module";
                break;
        case PAM_SYSTEM_ERR:
                retstring = "System error";
                break;
        case PAM_BUF_ERR:
		retstring = "Memory buffer error";
                break;
        case PAM_PERM_DENIED:
                retstring = "Permission denied";
                break;
        case PAM_AUTH_ERR:
		retstring = "Authentication failure";
                break;
        case PAM_CRED_INSUFFICIENT:
                retstring = "Can not access authentication data due to insufficient credentials";
                break;
        case PAM_AUTHINFO_UNAVAIL:
                retstring = "Underlying authentication service can not retrieve authenticaiton information";
                break;
        case PAM_USER_UNKNOWN:
                retstring = "User not known to the underlying authentication module";
                break;
        case PAM_MAXTRIES:
                retstring = "An authentication service has maintained a retry count which has been reached. No further retries should be attempted";
                break;
        case PAM_NEW_AUTHTOK_REQD:
                retstring = "New authentication token required. This is normally returned if the machine security policies require that the password should be changed beccause the password is NULL or it has aged";
                break;
        case PAM_ACCT_EXPIRED:
                retstring = "User account has expired";
                break;
        case PAM_SESSION_ERR:
                retstring = "Can not make/remove an entry for the specified session";
                break;
        case PAM_CRED_UNAVAIL:
                retstring = "Underlying authentication service can not retrieve user credentials unavailable";
                break;
        case PAM_CRED_EXPIRED:
                retstring = "User credentials expired";
                break;
        case PAM_CRED_ERR:
                retstring = "Failure setting user credentials";
                break;
        case PAM_NO_MODULE_DATA:
                retstring = "No module specific data is present";
                break;
        case PAM_CONV_ERR:
		retstring = "Conversation error";
                break;
        case PAM_AUTHTOK_ERR:
                retstring = "Authentication token manipulation error";
                break;
        case PAM_AUTHTOK_RECOVER_ERR:
                retstring = "Authentication information cannot be recovered";
                break;
        case PAM_AUTHTOK_LOCK_BUSY:
                retstring = "Authentication token lock busy";
                break;
        case PAM_AUTHTOK_DISABLE_AGING:
                retstring = "Authentication token aging disabled";
                break;
        case PAM_TRY_AGAIN:
                retstring = "Preliminary check by password service";
                break;
        case PAM_IGNORE:
                retstring = "Ignore underlying account module regardless of whether the control flag is required, optional, or sufficient";
                break;
        case PAM_ABORT:
                retstring = "Critical error (?module fail now request)";
                break;
        case PAM_AUTHTOK_EXPIRED:
                retstring = "User's authentication token has expired";
                break;
        case PAM_MODULE_UNKNOWN:
                retstring = "Module is not known";
                break;
        case PAM_BAD_ITEM:
                retstring = "Bad item passed to pam_*_item()";
                break;
        case PAM_CONV_AGAIN:
                retstring = "Conversation function is event driven and data is not available yet";
                break;
        case PAM_INCOMPLETE:
                retstring = "Please call this function again to complete authentication stack. Before calling again, verify that conversation is completed";
                break;

        default:
                retstring = "Authentication Failure!. You should not see this message.";
        }

        return retstring;

}

/* Courteously stolen from prelude-lml */
static int
generate_additional_data(idmef_alert_t *alert, const char *meaning, const char *data)
{
        int ret;
        prelude_string_t *str;
        idmef_additional_data_t *adata;

        ret = idmef_alert_new_additional_data(alert, &adata, -1);
        if ( ret < 0 )
                return ret;

        ret = idmef_additional_data_new_meaning(adata, &str);
        if ( ret < 0 )
                return ret;
        
        ret = prelude_string_set_ref(str, meaning);
        if ( ret < 0 )
                return ret;

        return idmef_additional_data_set_string_ref(adata, data);
}

extern void 
prelude_send_alert(pam_handle_t *pamh, int authval)
{

        int ret;

        prelude_log_set_flags(PRELUDE_LOG_FLAGS_SYSLOG);

        ret = pam_alert_prelude_init(pamh, authval);
        if ( ret < 0 )
                _pam_log(LOG_WARNING, 
                         "No prelude alert sent");

	prelude_deinit();

}

static int 
setup_analyzer(idmef_analyzer_t *analyzer)
{
        int ret;
        prelude_string_t *string;
        
        ret = idmef_analyzer_new_model(analyzer, &string);
        if ( ret < 0 )
                goto err;
        prelude_string_set_constant(string, ANALYZER_MODEL);

	ret = idmef_analyzer_new_class(analyzer, &string);
        if ( ret < 0 )
                goto err;
        prelude_string_set_constant(string, ANALYZER_CLASS);

	ret = idmef_analyzer_new_manufacturer(analyzer, &string);
        if ( ret < 0 )
                goto err;
        prelude_string_set_constant(string, ANALYZER_MANUFACTURER);

	ret = idmef_analyzer_new_version(analyzer, &string);
        if ( ret < 0 )
                goto err;
        prelude_string_set_constant(string, PAM_VERSION);

        
        return 0;

 err:
        _pam_log(LOG_WARNING, 
                        "%s: IDMEF error: %s.\n",
                        prelude_strsource(ret), prelude_strerror(ret));

        return -1;
}

static void 
pam_alert_prelude(const char *msg, void *data, pam_handle_t *pamh, int authval)
{
        int ret;
        idmef_time_t *clienttime;
        idmef_alert_t *alert;
        prelude_string_t *str;
        idmef_message_t *idmef = NULL;
        idmef_classification_t *class;
        prelude_client_t *client = (prelude_client_t *)data;
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_user_t *user;
        idmef_user_id_t *user_id;
        idmef_process_t *process;
        idmef_classification_t *classification;
        idmef_impact_t *impact;
        idmef_assessment_t *assessment;
        idmef_node_t *node;
	idmef_analyzer_t *analyzer;
	

        ret = idmef_message_new(&idmef);
        if ( ret < 0 ) 
                goto err;

        ret = idmef_message_new_alert(idmef, &alert);
        if ( ret < 0 )
                goto err;

        ret = idmef_alert_new_classification(alert, &class);
        if ( ret < 0 )
                goto err;

        ret = idmef_classification_new_text(class, &str);
        if ( ret < 0 )
                goto err;

        ret = prelude_string_new_ref(&str, msg);
        if ( ret < 0 )
                goto err;

        idmef_classification_set_text(class, str);

        ret = idmef_time_new_from_gettimeofday(&clienttime);
        if ( ret < 0 )
                goto err;
        idmef_alert_set_create_time(alert, clienttime);

        idmef_alert_set_analyzer(alert, 
                                 idmef_analyzer_ref(prelude_client_get_analyzer(client)), 
                                 0);

        /**********
         * SOURCE *
         **********/
        ret = idmef_alert_new_source(alert, &source, -1);
        if ( ret < 0 )
                goto err;

        /* BEGIN: Sets the user doing authentication stuff */
        ret = idmef_source_new_user(source, &user);
        if ( ret < 0 )
                goto err;
        idmef_user_set_category(user, IDMEF_USER_CATEGORY_APPLICATION);

        ret = idmef_user_new_user_id(user, &user_id, 0);
        if ( ret < 0 )
                goto err;
        idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_ORIGINAL_USER);

	if ( pam_get_item_ruser(pamh) ) {
	        ret = prelude_string_new(&str);
                if ( ret < 0 )
                        goto err;
	
	        ret = prelude_string_set_ref(str, pam_get_item_ruser(pamh));
                if ( ret < 0 )
                        goto err;

	        idmef_user_id_set_name(user_id, str); 
	}
        /* END */
        /* BEGIN: Adds TTY infos */
	if ( pam_get_item_tty(pamh) ) {
	        ret = prelude_string_new(&str);
                if ( ret < 0 )
                        goto err;

	        ret = prelude_string_set_ref(str, pam_get_item_tty(pamh));
                if ( ret < 0 )
                        goto err;

                idmef_user_id_set_tty(user_id, str);
	}
        /* END */
        /* BEGIN: Sets the source node (rhost) */
        ret = idmef_source_new_node(source, &node);
        if ( ret < 0 )
                goto err;
        idmef_node_set_category(node, IDMEF_NODE_CATEGORY_HOSTS);

	if ( pam_get_item_rhost(pamh) ) {
	        ret = prelude_string_new(&str);
                if ( ret < 0 )
                        goto err;

		ret = prelude_string_set_ref(str, pam_get_item_rhost(pamh));
                if ( ret < 0 )
                        goto err;

		idmef_node_set_name(node, str);
	}
        /* END */
        /* BEGIN: Describe the service */
        ret = idmef_source_new_process(source, &process);
        if ( ret < 0 )
                goto err;
        idmef_process_set_pid(process, getpid());

	if ( pam_get_item_service(pamh) ) {
	        ret = prelude_string_new(&str);
                if ( ret < 0 )
                        goto err;

		ret = prelude_string_set_ref(str, pam_get_item_service(pamh));
                if ( ret < 0 )
                        goto err;
        
		idmef_process_set_name(process, str);
	}
        /* END */

        /**********
         * TARGET *
         **********/

        ret = idmef_alert_new_target(alert, &target, -1);
        if ( ret < 0 )
                goto err;


        /* BEGIN: Sets the target node  */
	analyzer = prelude_client_get_analyzer(client);
        if ( ! analyzer ) goto err;

	node = idmef_analyzer_get_node(analyzer);
        if ( ! node ) goto err;
	idmef_target_set_node(target, node);
	node = idmef_node_ref(node);
        if ( ! node ) goto err;
	/* END */
        /* BEGIN: Sets the user doing authentication stuff */
        ret = idmef_target_new_user(target, &user);
        if ( ret < 0 )
                goto err;
        idmef_user_set_category(user, IDMEF_USER_CATEGORY_APPLICATION);

        ret = idmef_user_new_user_id(user, &user_id, 0);
        if ( ret < 0 )
                goto err;
        idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_TARGET_USER);

	if ( pam_get_item_user(pamh) ) {
	        ret = prelude_string_new(&str);
                if ( ret < 0 )
                        goto err;

		ret = prelude_string_set_ref(str, pam_get_item_user(pamh));
                if ( ret < 0 )
                        goto err;

		idmef_user_id_set_name(user_id, str); 
	}
        /* END */
        /* BEGIN: Short description of the alert */
        ret = idmef_alert_new_classification(alert, &classification);
        if ( ret < 0 )
                goto err;

        ret = prelude_string_new(&str);
        if ( ret < 0 )
                goto err;

        ret = prelude_string_set_ref(str, 
                                     authval == PAM_SUCCESS ? 
                                     "Authentication Success" : "Authentication Failure");
        if ( ret < 0 )
                goto err;

        idmef_classification_set_text(classification, str);
        /* END */
        /* BEGIN: Long description of the alert */
        ret = idmef_alert_new_assessment(alert, &assessment);
        if ( ret < 0 )
                goto err;

        ret = idmef_assessment_new_impact(assessment, &impact);
        if ( ret < 0 )
                goto err;

        ret = prelude_string_new(&str);
        if ( ret < 0 )
                goto err;

        ret = prelude_string_set_ref(str, 
                                     pam_get_alert_description(authval));
        if ( ret < 0 )
                goto err;

        idmef_impact_set_description(impact, str);
        /* END */
        /* BEGIN: Adding additional data */
	if ( pam_get_item_user_prompt(pamh) ) {
	        ret = generate_additional_data(alert, "Local User Prompt", 
                                               pam_get_item_user_prompt(pamh));
                if ( ret < 0 )
                        goto err;
        }
        /* END */

        prelude_client_send_idmef(client, idmef);
 
        if ( idmef )
                idmef_message_destroy(idmef);

	return;
 err:
        _pam_log(LOG_WARNING,
                        "%s: IDMEF error: %s.\n",
                        prelude_strsource(ret), prelude_strerror(ret));
        
        if ( idmef )
                idmef_message_destroy(idmef);

}

static int
pam_alert_prelude_init(pam_handle_t *pamh, int authval)
{

        int ret;
        prelude_client_t *client = NULL;

        ret = prelude_init(NULL, NULL);
        if ( ret < 0 ) {
                _pam_log(LOG_WARNING, 
                         "%s: Unable to initialize the Prelude library: %s.\n",
                         prelude_strsource(ret), prelude_strerror(ret));
                return -1;
        }

        ret = prelude_client_new(&client, DEFAULT_ANALYZER_NAME);
        if ( ! client ) {
                _pam_log(LOG_WARNING, 
                         "%s: Unable to create a prelude client object: %s.\n",
                         prelude_strsource(ret), prelude_strerror(ret));

                return -1;
        }


        ret = setup_analyzer(prelude_client_get_analyzer(client));
        if ( ret < 0 ) {
                _pam_log(LOG_WARNING,
                         "%s: Unable to setup analyzer: %s\n",
                         prelude_strsource(ret), prelude_strerror(ret));

		prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_FAILURE);

		return -1;
        }

        ret = prelude_client_start(client);
        if ( ret < 0 ) {
                _pam_log(LOG_WARNING, 
                         "%s: Unable to initialize prelude client: %s.\n",
                         prelude_strsource(ret), prelude_strerror(ret));
 
		prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_FAILURE);

                return -1;
        }

        pam_alert_prelude("libpam alert" , client, pamh, authval);

	prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);

        return 0;
}

#endif PRELUDE

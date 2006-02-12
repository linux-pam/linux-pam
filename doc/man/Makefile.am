#
# Copyright (c) 2006 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = *~

EXTRA_DIST = $(MANS) $(XMLS)

man_MANS = pam.8 pam.conf.5 pam.d.5 \
	pam_acct_mgmt.3 pam_authenticate.3 \
	pam_chauthtok.3 pam_close_session.3 \
	pam_end.3 \
	pam_fail_delay.3 \
	pam_get_data.3 pam_get_item.3 \
	pam_open_session.3 \
	pam_set_data.3 pam_set_item.3 \
	pam_setcred.3 pam_start.3 pam_strerror.3
XMLS = pam.8.xml \
	pam_acct_mgmt.3.xml pam_authenticate.3.xml \
	pam_chauthtok.3.xml pam_close_session.3.xml \
	pam_end.3.xml \
	pam_fail_delay.3.xml \
	pam_get_data.3.xml pam_get_item.3.xml \
	pam_open_session.3.xml \
	pam_set_data.3.xml pam_set_item.3.xml \
	pam_setcred.3.xml pam_start.3.xml pam_strerror.3.xml \
	pam_item_types.inc.xml

if ENABLE_REGENERATE_MAN
pam_get_item.3: pam_item_types.inc.xml
pam_set_data.3: pam_item_types.inc.xml
-include $(top_srcdir)/Make.xml.rules
endif

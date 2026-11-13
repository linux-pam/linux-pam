#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <test_assert.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main()
{
    pam_handle_t *pamh=NULL;
    int retval;
    const struct pam_message msg[1] = {
	{
		    .msg = "misc_conv_test",
		    .msg_style = PAM_TEXT_INFO
	}
    };
    const struct pam_message *msgm = &msg[0];
    struct pam_response *resp = NULL;
    struct pam_response **r = NULL;

    ASSERT_EQ(PAM_SUCCESS, pam_start("tst-pam_misc_conv", NULL, &conv, &pamh));

    /* msgm == NULL */
    ASSERT_EQ(PAM_CONV_ERR, misc_conv(1, NULL, r, NULL));

    /* r == NULL */
    ASSERT_EQ(PAM_SUCCESS, retval=misc_conv(1, &msgm, r, NULL));
    ASSERT_EQ(NULL, r);

    /* *r == NULL */
    r = &resp;
    ASSERT_EQ(PAM_SUCCESS, retval=misc_conv(1, &msgm, r, NULL));
    ASSERT_NE(NULL, *r);
    free(*r);

    ASSERT_EQ(PAM_SUCCESS, pam_end(pamh,retval)); /* close Linux-PAM */

    return 0;
}

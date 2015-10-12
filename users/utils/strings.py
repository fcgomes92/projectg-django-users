from django.utils.translation import ugettext as _

__author__ = 'gomes'

LOGIN_SUCCESS = _("Successful login!")
LOGIN_ERR = _("Login err!")
LOGIN_EMAIL_ERR = _("Wrong email!")

PASSWORD_MISMATCH = _("The two password fields didn't match.")
LBL_EMAIL = _("Email")
LBL_PASSWORD = _("Password")
LBL_NEW_PASSWORD = _("New Password")
LBL_NEW_PASSWORD_CONFIRM = _("New password confirmation")

REGISTER_MAIL_SENT = _('Please check your email!')
REGISTER_MAIL_ERR = _('Invalid email!')
REGISTER_MAIL_REGISTERED = _('Registered email! Try to reset your password!')

REGISTER_CONFIRMATION = _('Thanks! Now you can login!')
REGISTER_CONFIRMATION_ERR = _('Error! Contact the admin!')

RESET_PASSWORD_CONFIRM = _("An email has been sent to {}. Please check its inbox to continue resetting password.")
RESET_PASSWORD_ERR_NO_EMAIL = _('No user is associated with this email address')
RESET_PASSWORD_ERR_FORMAT_EMAIL = _('Invalid Input')